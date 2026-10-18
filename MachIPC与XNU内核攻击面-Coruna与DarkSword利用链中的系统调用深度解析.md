# Mach IPC与XNU内核攻击面——Coruna与DarkSword利用链中的系统调用深度解析

## 摘要

Mach微内核机制与BSD系统调用的融合构成了XNU内核的核心架构。Mach IPC作为iOS进程间通信的基石，其端口语义、内存管理接口（mach_vm_*）和任务/线程控制接口，既是系统正常运行的基础设施，也是高级攻击者的核心攻击面。本文从XNU内核架构出发，深入分析Mach系统调用在Coruna和DarkSword攻击中的关键作用，揭示内核接口设计中的安全权衡。

---

## 第一章 XNU双内核架构概览

### 1.1 Mach + BSD的共生设计

XNU（"X is Not Unix"）是macOS/iOS使用的混合内核。它将Mach微内核的IPC机制和BSD内核的传统Unix语义融合在单一地址空间：

```
┌─────────────────────────────────────────────────┐
│                    XNU Kernel                     │
├──────────────────┬──────────────────────────────┤
│   Mach Layer     │        BSD Layer              │
│  (IPC/Memory)    │   (POSIX/File/Net)           │
├──────────────────┴──────────────────────────────┤
│              IOKit Driver Framework              │
├─────────────────────────────────────────────────┤
│         Hardware Abstraction (ARM64)             │
└─────────────────────────────────────────────────┘

关键特性：
  - Mach系统调用通过Mach trap进入（SVC + trap号）
  - BSD系统调用通过unix_syscall86分发
  - 两者共享同一内核地址空间
  - Mach提供IPC/VM/线程原语
  - BSD提供文件/网络/进程语义
```

### 1.2 Mach Trap入口

iOS上的Mach系统调用通过trap门控进入：

```c
// 内核trap表（简化）
const struct {
    uint32_t number;
    void *handler;
    uint32_t flags;
    uint32_t arg_count;
} mach_trap_table[] = {
    {mach_msg_trap,      &mach_msg_overwrite,     0, 7},
    {mach_msg_overwrite,  &mach_msg_overwrite,     0, 7},
    {vm_allocate_trap,    &mach_vm_allocate,       0, 3},
    {vm_deallocate_trap,  &mach_vm_deallocate,     0, 2},
    {vm_protect_trap,     &mach_vm_protect,        0, 4},
    {task_info_trap,      &task_info,              0, 3},
    {task_for_pid_trap,   &convert_task_to_task,   TBF_RETURNARGS, 2},
    {thread_create_trap,  &thread_create,          0, 3},
    // ... 约200+个trap
};
```

系统调用编号范围决定了攻击者可达的内核接口集合。

### 1.3 用户-内核边界机制

iOS中从用户态到内核态的转移受多重保护：

```
用户态系统调用路径：
  1. 函数存根（libSystem）加载syscall号到eax
  2. SVC #0x80 触发异常（从EL0到EL1）
  3. 内核异常向量分发
  4. 检查系统调用号有效性
  5. 参数验证（用户空间指针检查）
  6. 执行内核逻辑
  7. 结果写回用户空间
  8. ERET 返回用户态

安全约束：
  - PAN（Privileged Access Never）：内核不能直接读写用户页
  - KPTI：内核页表与用户页表隔离
  - 参数拷贝通过copyin/copyout验证地址范围
```

---

## 第二章 Mach虚拟内存接口攻击面

### 2.1 mach_vm_* 系列接口

Mach虚拟内存接口是iOS中最强大的用户态-内核交互通道之一：

```c
kern_return_t mach_vm_allocate(
    vm_map_t target,           // 目标task的虚拟地址空间
    mach_vm_address_t *address, // 分配地址（输入/输出）
    mach_vm_size_t size,       // 大小
    int flags                   // 标志位
);

kern_return_t mach_vm_protect(
    vm_map_t target_task,
    mach_vm_address_t address,
    mach_vm_size_t size,
    boolean_t set_maximum,
    vm_prot_t new_protection    // 新的内存保护位
);

kern_return_t mach_vm_read_overwrite(
    vm_map_t target_task,      // 目标地址空间！
    mach_vm_address_t address, // 要读取的地址
    mach_vm_size_t size,
    mach_vm_address_t data,    // 数据写入的用户缓冲区
    mach_vm_size_t *outsize
);

kern_return_t mach_vm_region(
    vm_map_t target,           // 查询目标地址空间布局
    mach_vm_address_t *address,
    mach_vm_size_t *size,
    vm_region_flavor_t flavor,
    vm_region_info_t info,
    mach_msg_type_number_t *infoCnt,
    mach_port_t *object_name
);
```

### 2.2 关键攻击能力

这些接口为攻击者提供了以下能力（前提是有目标task的port right）：

| 接口 | 攻击能力 | 利用场景 |
|------|---------|---------|
| mach_vm_read | 读取任意进程内存 | 信息泄露/ASLR绕过 |
| mach_vm_write | 写入任意进程内存 | 代码注入/篡改 |
| mach_vm_protect | 修改内存保护 | W^X绕过 |
| mach_vm_region | 枚举地址空间布局 | KASLR绕过 |
| mach_vm_map | 映射内核对象到用户空间 | 内核对象操作 |
| mach_vm_copy | 进程间内存复制 | 数据窃取 |

### 2.3 Coruna中的mach_vm_use

Coruna利用链在获得WebContent内的任意读写后，使用Mach VM接口的路径：

```
步骤1：提取task port
  → 在WebContent进程中扫描Mach消息缓冲区
  → 找到指向自身或host的task port引用

步骤2：枚举内核地址空间
  → 通过host_get_special_port获取特殊端口
  → mach_vm_region遍历内核映射区域
  → 识别内核代码/数据/栈的基地址

步骤3：信息收集
  → 读取内核结构以定位关键函数（panic, kauth等）
  → 解析Mach-O头部定位ROP gadget
  → 构建绕过PAC的合法跳转链
```

### 2.4 DarkSword中的mach_vm_write利用

DarkSword利用mach_vm_write的场景更为直接：

```
步骤1：通过IOSurface漏洞获得内核任意读写
步骤2：定位目标进程的虚拟地址空间
步骤3：直接修改目标进程的用户内存
  → 修改代码段注入shellcode（绕过代码签名）
  → 修改函数指针劫持控制流
  → 修改进程cred结构提权
```

---

## 第三章 Mach消息机制的安全属性

### 3.1 mach_msg结构

Mach消息是内核中进程通信的基本单元：

```c
struct mach_msg {
    mach_msg_header_t header;    // 消息头
    // 可选：
    mach_msg_body_t body;        // OOL描述符数量
    mach_msg_ool_descriptor_t ool[0]; // 外联数据描述
    // 可选：
    mach_msg_port_descriptor_t ports[0]; // 携带的端口引用
    // ...
};

typedef struct {
    natural_t msgh_bits;
    natural_t msgh_size;
    mach_port_t msgh_remote_port;
    mach_port_t msgh_local_port;
    mach_port_name_t msgh_voucher_port;
    mach_msg_id_t msgh_id;
} mach_msg_header_t;
```

### 3.2 外联内存（OOL）的攻击面

Mach消息的OOL机制允许发送进程向接收进程传递内存引用。这个过程涉及内核内存管理的关键路径：

```
OOL发送：
  用户进程 → mach_msg(body含OOL描述符)
  → 内核：vm_object引用计数增加
  → 内核：页表映射到接收进程

OOL接收：
  接收进程调用mach_msg → 内核分配内存描述
  → 用户进程通过mach_memory_destroy释放

攻击点：
  - OOL描述符中地址验证不严 → 可能引用特权内存
  - 竞态：发送后释放 → 接收时已无效
  - 引用计数错误 → UAF基础
```

### 3.3 端口引用与消息伪造

Mach消息中的端口字段可被构造为任意值。内核通过`msgh_bits`中的类型字段（SEND, SEND_ONCE等）决定如何处理：

```c
// msgh_bits中端口类型编码
#define MACH_MSG_SEND_RIGHT     0x20
#define MACH_MSG_SEND_ONCE      0x10
#define MACH_MSG_PORT_DESCRIPTOR 0x2000

// 攻击场景：
// 如果攻击者构造了包含SEND_ONCE端口的消息
// 目标服务回复时会将回复权利发送给攻击者指定的端口
// → 实现了"欺骗服务向错误端口发送消息"
```

Coruna利用中，攻击者通过修改WebContent进程中已排队的Mach消息头，将`msgh_remote_port`改为攻击者控制的端口，实现了消息路由劫持。

### 3.4 特殊端口与权限边界

iOS中的特殊端口代表不同级别的系统权限：

```
host_get_special_port(host, which, &port)
  which = HOST_PRIV_PORT → 主机特权操作
  which = HOST_IO_MASTER_PORT → IOKit主端口（访问所有驱动！）
  which = HOST_MAX_SPECIAL_PORT → 各种内部服务端口

task_get_special_port(task, which, &port)
  which = TASK_KERNEL_PORT → 目标task的完全控制
  which = TASK_INSPECT_PORT → 读取task内存
  which = TASK_READ_PORT / TASK_LOOKUP_PORT → 受限查询
```

关键攻击向量：
- **HOST_IO_MASTER_PORT**：通过此端口可查找任何IOKit服务，是DarkSword中进入IOKit攻击路径的入口
- **task port**：持有任意进程的task port意味着对该进程的完全VM控制

---

## 第四章 系统调用中的安全缺陷模式

### 4.1 TOCTOU竞态漏洞

XNU内核中检查与使用之间的时间窗口是经典漏洞模式：

```c
// 伪代码：有TOCTOU缺陷的系统调用
kern_return_t vulnerable_call(user_addr_t addr, size_t len) {
    // 检查：地址在用户空间范围内
    if (!user_range_valid(addr, len)) {
        return KERN_INVALID_ADDRESS;
    }
    
    // 竞态窗口：攻击者可在此处unmap + remap
    // addr已变为内核地址！
    
    // 使用：直接通过addr访问内存
    copyin(addr, kernel_buf, len);  // ← 可能读内核内存
}
```

iOS的缓解措施：
- copyin/copyout内部重新验证地址
- 但某些路径使用快速假设（trusting validated）
- 多线程场景：验证线程与使用线程的同步不完美

### 4.2 整数溢出与内存分配

Mach VM接口中大量使用64位大小参数，不当的算术运算可导致溢出：

```c
// 经典模式
kern_return_t bad_alloc(mach_vm_size_t size) {
    // 未检查溢出
    vm_offset_t kernel_copy_size = size + HEADER_SIZE;
    // 若size接近UINT64_MAX → kernel_copy_size回绕为小值
    
    vm_map_copyin(target_map, addr, kernel_copy_size, FALSE, &copy);
    // 分配了小的kernel buffer
    // 但后续按原始size拷贝 → 内核缓冲区溢出
}
```

DarkSword的IOSurface漏洞涉及类似模式：用户提供的尺寸参数在内部计算中发生截断或回绕。

### 4.3 引用计数错误

内核对象通过引用计数管理生命周期。错误计数导致UAF：

```c
// IOKit对象引用管理
void handle_user_method(IOUserClient *client, ...) {
    OSObject *target = get_object_from_registry(client);
    
    // 场景：
    // 1. target->retain() → refCount = 2
    // 2. 另一线程关闭服务 → target->release() → refCount = 1
    // 3. 当前线程操作target完成 → target->release() → refCount = 0
    // 4. 但另一线程仍持有指针（本应refCount > 0）
    // 5. 内存被释放后重用 → UAF
}
```

---

## 第五章 IOKit用户客户端的安全分析

### 5.1 IOKit架构与攻击面

IOKit是macOS/iOS的设备驱动框架，通过用户态客户端（IOUserClient）暴露内核驱动接口：

```
用户态                    内核态
┌──────────────┐   ┌────────────────────────┐
│ IOConnect... │──►│ IOUserClient::        │
│              │   │   externalMethod()    │
│ IOKit服务    │   │                      │
│ 匹配/发现    │   │ 驱动特定代码          │
└──────────────┘   └────────────────────────┘

关键API：
  IOServiceGetMatchingService() → 发现驱动服务
  IOServiceOpen() → 建立用户-内核通信通道
  IOConnectCallMethod() → 调用驱动方法（传递参数）
  IOConnectCallStructMethod() → 传递结构体参数
```

### 5.2 IOSurface：零拷贝GPU共享的攻击面

IOSurface是iOS的GPU内存共享框架，允许不同进程通过内核对象引用同一块物理内存：

```
IOSurface安全模型：
  1. 进程A创建IOSurface（指定大小、属性）
  2. 内核分配物理页 → 建立IOSurface对象
  3. 进程A获得IOSurface ID（mach_port_t）
  4. 通过Mach IPC将ID传递给进程B
  5. 进程B调用IOSurfaceMap映射到自己地址空间

攻击场景（DarkSword漏洞3）：
  - 用户通过IOConnectCallStructMethod传入畸形参数
  - 内核IOSurface处理函数未严格验证
  - 触发越界读写 → 破坏相邻内核对象
  - 构造UAF → 获得任意内核读写能力
```

### 5.3 内核中IOKit驱动的权限模型

```c
// IOKit驱动的权限声明
// 通过驱动info plist定义

// 关键安全属性：
//   IOUserClientClass → 暴露的用户客户端类型
//   IOMatchCategory → 匹配条件（控制谁能打开）
//   IOUserClientGatedSelector → 需要额外权限的方法

// 问题：许多驱动的某些method不检查调用者权限
// 任意进程只要能IOServiceOpen就能调用
// → 沙箱策略对IOKit调用控制有限
```

### 5.4 DarkSword的IOKit攻击路径

```
1. WebContent漏洞获得任意读写
2. 泄露host_priv端口
3. host_get_special_port(HOST_IO_MASTER_PORT)
4. IOServiceGetMatchingService("IOSurfaceFastMemory")
5. IOServiceOpen() → 获取IOUserClient连接
6. IOConnectCallStructMethod(selector=3, inputBuffer=畸形数据)
7. 触发内核IOSurface驱动中的验证缺陷
8. 实现内核态内存破坏
```

---

## 第六章 内核信息泄露防御

### 6.1 KASLR与地址空间随机化

iOS内核使用多级随机化：

```
KASLR层次：
  1. 内核代码基址随机化（slide量）
  2. 内核栈随机化（每次系统调用不同位置）
  3. 内核对象分配随机化（zone hash扰动）
  4. KPTI：用户页表不包含内核映射

绕过需求：
  - 攻击者至少需要一个信息泄露漏洞
  - 常见来源：mach_vm_region返回的内核区域大小
  - IOSurface映射信息暴露物理地址
  - 未初始化的内核栈/堆内存拷贝到用户空间
```

### 6.2 信息泄露缓解措施

iOS近年的加固：

- **copyin/copyout**：内核数据通过验证的拷贝函数传递，禁止直接指针
- **Zone分配器**：内核对象分配器对未初始化内存进行清洗
- **返回大小限制**：某些Mach调用返回固定结构体而非动态大小
- **审计日志**：异常的信息查询模式被记录

### 6.3 侧信道信息泄露

即使直接泄露被堵住，间接通道仍然存在：

```
微架构侧信道：
  - Spectre v2：通过分支预测窃取内核内存
  - MDS/TSX：通过缓冲区采样获取近期内核数据
  - Cache timing：探测内核数据结构布局

时间侧信道：
  - 不同地址范围访问延迟差异 → 推断页表布局
  - 系统调用错误码时序 → 推断内部状态

iOS应对：
  - 分支预测器隔离（per-context）
  - 禁用SMT（iOS本身无SMT）
  - 关键路径常数时间实现
```

---

## 第七章 内核提权技术路径

### 7.1 从任意读写到特权提升

获得内核任意读写后的标准提权路径：

```
路径1：修改cred结构
  1. 找到当前进程的ucred结构（通过proc → p_ucred）
  2. 修改cr_uid = 0, cr_gid = 0
  3. 添加cr_flags |= CR_ROOT
  → 完成：进程以root权限运行

路径2：修改sandbox profile
  1. 找到当前进程的sandbox引用（sb_xsb）
  2. 替换为host的宽松profile
  或 3. 直接置NULL解除沙箱
  → 完成：沙箱逃逸

路径3：替换函数指针
  1. 修改内核syscall表的handler指针
  2. 或修改hook点（mac_*_ops结构）
  → 完成：内核代码执行

路径4：ROP直接执行提权gadget
  1. 找到内核中调用set_cred的代码段
  2. 构造ROP链触发它
  3. 需要同时满足PAC + CFI
  → 完成：不修改任何数据结构即提权
```

### 7.2 macOS/iOS特有的提权挑战

iOS内核提权比macOS更困难：

- **代码签名强制**：内核不能加载未签名代码 → 纯ROP（无shellcode注入）
- **PAC + CFI**：函数指针修改后跳转仍需合法签名
- **Sandbox**：提权后仍需解除沙箱才能自由操作
- **AMFI（Apple Mobile File Integrity）**：额外验证层

### 7.3 DarkSword的cred修改链

```
1. 通过IOKit UAF获得任意内核读写原语
2. 定位当前进程的proc结构
   - 从current_thread() → 栈指针 → 找到thread结构
   - thread → task → proc → ucred
3. 备份原始cred（用于后续恢复）
4. 修改cred为root + 解除沙箱
5. 执行特权操作（安装持久化后门）
6. 恢复原始cred（减少检测风险）
```

---

## 第八章 未来内核攻击面收敛趋势

### 8.1 Tightbeam IPC（iOS 18+）

Apple正在用Tightbeam替代传统Mach消息的部分场景：

```
设计目标：
  - 减少消息传递中的端口引用暴露
  - 消息级别能力验证（非仅端口级别）
  - 内存拷贝路径形式化验证
  - 统一的用户-内核边界检查

对攻击面的影响：
  - OOL描述符处理更严格
  - 端口传递需要显式能力令牌
  - 消息伪造检测增强
  - 但引入新的代码路径 = 新的潜在缺陷
```

### 8.2 SPTM下的内核攻击面变化

```
当前模型：
  内核管理所有页表 → 攻破内核 = 控制所有内存
  IOKit驱动运行在内核态 → 驱动漏洞 = 内核漏洞

SPTM模型：
  页表由SPTM管理 → 内核即使被攻破也无法直接控制映射
  IOKit关键驱动移入TXM → 驱动漏洞不再直接等同内核攻破
  内核被分区（多个World）→ 单World失陷不扩散
```

### 8.3 形式化验证的系统调用

Apple安全团队的方向：

- 对关键Mach系统调用进行形式化验证
- 自动证明参数检查路径的完备性
- 静态分析发现TOCTOU模式
- 内核代码路径覆盖审计（模糊测试辅助）

---

## 第九章 防御工程实践

### 9.1 最小化系统调用暴露

iOS 17+的做法：

```
WebContent沙箱中：
  ✗ mach_vm_read / mach_vm_write（禁止操作其他task）
  ✗ task_for_pid（绝对禁止非特权进程）
  ✗ host_get_special_port(HOST_IO_MASTER_PORT)
  ✓ mach_msg（自身端口通信）
  ✓ vm_allocate（自身地址空间）
  ✓ 极少量渲染相关系统调用

原则：每个沙箱域仅暴露该域功能所需的最小系统调用集
```

### 9.2 IOKit接口审计清单

对驱动开发者/安全团队的审计建议：

```
□ IOConnectCallMethod的参数数量/类型验证
□ IOConnectCallStructMethod的输入缓冲区大小检查
□ 用户指定地址的copyin前二次验证
□ OOL内存的引用计数路径完整审查
□ 竞态条件：多selector调用的锁保护
□ 返回值是否泄露内核地址/布局信息
□ 用户客户端关闭时的资源释放顺序
```

### 9.3 系统调用监控与异常检测

设备级防御中的行为监测：

```
高置信攻击指标：
  - 短时间内大量mach_vm_region调用
  - 非正常的host_get_special_port请求
  - WebContent进程发起IOServiceOpen
  - 同一selector的IOConnectCallMethod异常高频
  - task port在进程间异常传递
```

---

## 第十章 总结

Mach IPC和XNU系统调用接口构成了iOS内核攻击的核心通道。Coruna和DarkSword的利用链清晰展示了：

1. **VM接口是双刃剑**：mach_vm_*提供了强大的内存操作能力，也成为攻击者进行信息收集和篡改的关键工具
2. **IOKit是沙箱盲区**：用户态到内核态的驱动接口是沙箱策略难以完全覆盖的攻击面
3. **端口安全是基础**：Mach端口的传递和验证机制的每一个弱点都可能被组合利用
4. **纵深防御必须多层**：信息泄露→内存破坏→权限修改→持久化——每一环都需要独立阻断

XNU内核的攻击面正在通过SPTM/TXM和Tightbeam等下一代架构逐步收敛，但在过渡期内，理解现有接口的安全语义仍然是iOS漏洞研究和攻防对抗的基础。

---

## 参考资源

- XNU Kernel Source: https://opensource.apple.com/source/xnu/
- Mach IPC Reference - Apple Developer Documentation
- IOKit Device Driver Programming Guide
- Coruna Exploit Analysis - Lookout Threat Intelligence (2024)
- DarkSword: Six Vulnerabilities Deep Dive - Meta Security (2025)
- iOS Kernel Exploitation - Pangu Team Technical Reports
- Apple Platform Security: Kernel Integrity Protection (2024-2026)
