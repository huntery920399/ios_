# ARM指针认证码PAC绕过技术前沿——从Coruna到DarkSword的控制流攻击实践

## 摘要

ARMv8.3引入的指针认证码（PAC）机制是Apple在A12芯片之后部署的核心控制流保护技术。PAC通过在指针中嵌入加密签名来检测指针篡改，理论上阻断了传统ROP（Return-Oriented Programming）攻击。然而Coruna和DarkSword两起攻击事件中，攻击者展示了多种PAC绕过策略，证明了即使硬件级安全机制也无法单独构成不可突破的防线。本文系统分析PAC的密码学原理、iOS中的具体实现、已知的绕过方法论以及未来控制流保护的演进方向。

---

## 第一章 PAC机制密码学基础

### 1.1 QARMA5算法

Apple选用的PAC签名算法是基于QARMA5的变体。QARMA5是一种轻量级分组密码，专为指针认证场景设计：

```
输入：
  - 指针值 (64位，但实际有效位约55位)
  - Modifier (上下文数据，如栈指针值)
  - 密钥 (512位，存储在系统寄存器中)

输出：
  - 16位PAC字段（A12-A15芯片）
  - 3位PAC + 保留位（部分实现）

算法特点：
  - 5轮Feistel网络（非SPN结构）
  - 每轮4个S-BOX + 线性层
  - 优化了面积和延迟（适合片上实现）
  - 抗差分/线性分析保证16位安全强度
```

PAC的核心设计约束是：生成的16位认证码必须足够短以容纳在高地址位中，同时提供足够的安全强度。16位意味着攻击者盲目猜测的成功率为 1/65536。

### 1.2 PAC密钥类型与用途

ARM架构定义了多个PAC密钥，各自用于不同的认证场景：

```
APIAKey / APIAKey_EL1  → PACIA / PACIA SP (指令地址认证)
APIBKey / APIBKey_EL1  → PACIB / PACIB SP (数据地址认证)
APDAKey / APDAKey_EL1  → PACDA (数据指针认证)
APDBKey / APDBKey_EL1  → PACDB (备用数据指针)
APGAKey / APGAKey_EL1  → PACGA (通用认证，不嵌入指针)
```

iOS中的密钥管理：
- **EL0密钥**（应用层）：每个进程独立派生，通过内核初始化
- **EL1密钥**（内核层）：全系统共享，启动时由Secure Boot链注入
- **密钥轮换**：进程创建时重新派生EL0密钥，防止跨进程伪造

### 1.3 PAC编码位置

ARM64地址空间中，有效虚拟地址通常使用低48位（iOS实际47位）。PAC编码在高地址的未使用位中：

```
64位指针布局（A14+，TBI启用）：

 63          55  54  53  52-48   47          16  15   0
┌────────────┬───┬───┬──────┬────────────────┬────┬────┐
│   PAC字段  │ 1 │ 1 │  Type│  VA[52:48]     │VA  │ 0  │
│  (8 bits)  │   │   │      │  (保留位)       │    │    │
└────────────┴───┴───┴──────┴────────────────┴────┴────┘

注：实际编码取决于TBI/EPN/EXCL配置
A12芯片：5位PAC + 11位保留
A14+芯片：7位PAC + 扩展地址支持
```

---

## 第二章 iOS中PAC的部署策略

### 2.1 系统二进制PAC覆盖率

iOS中的PAC部署遵循分层策略：

```
全覆盖PAC：
  - 内核代码（所有函数prologue/epilogue使用PACIA+AUTIA）
  - libsystem_c.dylib（C标准库）
  - libobjc.A.dylib（ObjC运行时）
  - 核心框架（Foundation, CoreFoundation）
  - Safari/WebKit（所有C++代码路径）

部分PAC：
  - 第三方框架
  - 动态库中的热点函数

无PAC：
  - 纯数据页面（使用PACDA可选）
  - JIT生成的代码（特殊保护）
  - 早期启动阶段代码（密钥未初始化）
```

### 2.2 函数签名模板

iOS ARM64e函数的标准保护模式：

```asm
; 典型PAC保护的函数
_target_function:
    pacibsp                    ; 用SP作为modifier签名LR
    stp     fp, lr, [sp, #-16]! ; 保存帧指针和返回地址
    mov     fp, sp
    ; ... 函数体 ...
    ldp     fp, lr, [sp], #16
    autibsp                    ; 验证LR签名
    ret                        ; 返回（若验证失败则触发异常）
```

攻击者面临的约束：
1. 修改LR值 → AUTIBSP检测到签名错误 → 异常 → 进程终止
2. 需要同时伪造有效的PAC码
3. PAC密钥对攻击者不可见（存储在系统寄存器中）

### 2.3 JIT区域与PAC例外

JavaScriptCore等JIT引擎的代码页不能直接使用标准PAC保护（因为代码在运行时动态生成）。iOS为JIT设置了特殊处理：

- JIT代码区域使用独立的W^X策略
- 从JIT代码跳转到已签名代码需要特殊的"签名桥"
- JIT缓冲区中的函数指针仍需PAC认证
- 这创建了一个"PAC信任边界"——JIT区域内部的操作不受PAC约束

---

## 第三章 PAC绕过方法论分类

### 3.1 签名预言机攻击（PAC Oracle）

最常见的绕过策略不是"破解"密码，而是"请求合法签名"：

```
攻击模型：
  找到程序中的PACIA/PACIB指令
  该指令以攻击者可控的数据作为modifier
  如果攻击者能控制待签名指针值 + modifier
  → 程序自己为攻击者生成了合法PAC

条件要求：
  1. 目标代码中存在 pacia/pacib 指令
  2. 攻击者能控制传入的指针值（被签名的数据）
  3. 攻击者能预测或控制modifier（通常是SP或另一寄存器）
  4. 签名结果可被攻击者读取（泄露路径）
```

Coruna利用中，攻击者在WebKit的JIT编译路径中找到了满足条件的gadget序列。

### 3.2 签名复用与跨域攻击

```
核心观察：
  同一密钥下，如果两个指针 (ptr1, mod1) 和 (ptr2, mod2) 
  恰好生成相同的签名（16位碰撞概率1/65536）
  → 可以互换使用

实际攻击：
  1. 收集大量已签名的 (target_addr, modifier) → PAC 对
  2. 构建"签名表"——预计算可用的跳转目标
  3. 利用栈迁移使SP匹配表中某个modifier
  4. 从表中选取对应条目实现跳转
```

这种方法需要大量信息泄露来收集签名对，且受限于可用gadget数量。

### 3.3 密钥泄露攻击

理论上最"暴力"的绕过——直接获取PAC密钥：

```
密钥访问路径：
  - EL0代码永远无法直接读取APIAKey等寄存器
  - 仅可通过msr/mrs在EL1访问（内核权限）
  - 内核初始化时的密钥派生过程可能存在侧信道
  
iOS特有的保护：
  - 密钥寄存器受MPAM/Secure Monitor保护
  - 上下文切换时密钥保存/恢复路径是攻击目标
  - 进程fork后密钥重新派生→派生算法是攻击面

实际难度：极高
  - 需要内核级信息泄露 + 侧信道能力
  - 目前没有公开的直接PAC密钥泄露案例
```

### 3.4 认证旁路（跳过AUT检查）

如果PAC保护依赖于函数返回时执行AUT指令，则跳过该检查即可绕过：

```asm
; 正常路径
    ...
    autibsp    ; 检查LR签名
    ret        ; 返回

; 攻击路径：找到ret指令本身
    ; 如果攻击者能直接跳转到 ret 前一条指令
    ; 且不经过autibsp
    ; → 伪造的LR被直接使用

; 但现代iOS中
    ; ret指令本身也受PAC保护
    ; BLRAA/BRRAA等间接跳转需要AUT
    ; 使纯旁路越来越困难
```

### 3.5 内核PAC信任边界攻击

iOS内核中的PAC密钥不同于用户态。特定内核路径在验证PAC前会解除保护：

```
攻击场景：
  1. 内核接收到用户态系统调用
  2. 参数从用户空间拷贝到内核
  3. 某些代码路径在内核PAC验证之前使用这些参数
  
条件：
  - 内核中存在"先使用后验证"的代码缺陷
  - 参数被解释为函数指针/返回地址
  - 攻击者控制的值通过拷贝路径进入执行
```

---

## 第四章 Coruna中的PAC绕过实践

### 4.1 WebKit JIT作为签名预言机

Coruna（2024年曝光的间谍软件活动）在利用CVE-2024-23222后，需要绕过WebContent进程的PAC保护。其核心策略：

```
阶段1：内存破坏获取任意读写
  → 此时可以读取进程内任意已签名指针

阶段2：定位PAC保护代码
  → WebContent进程中的系统库函数已PAC签名

阶段3：签名提取
  → 从进程地址空间中读取有效PAC对
  → (addr_with_pac, corresponding_modifier)

阶段4：构造合法跳转
  → 使用提取的签名构造合法的控制流转移
  → 在不修改已签名值的前提下实现ROP
```

关键洞察：Coruna并非"破解"了PAC，而是利用了WebContent进程中大量合法的签名指针作为"gadget源"。

### 4.2 跨进程签名差异利用

iOS不同进程的PAC密钥由不同派生路径生成。Coruna利用的微妙点：

- WebContent与Networking进程共享部分系统框架
- 某些共享代码段的PAC验证在特定上下文中宽松
- Mach消息处理代码中的PAC验证路径有边界条件

---

## 第五章 DarkSword的多层PAC绕过

### 5.1 六漏洞链中的PAC角色

DarkSword（2025年曝光）的六漏洞利用链中，PAC绕过是贯穿多个阶段的必要条件：

```
漏洞1 (WebKit RCE) → 获得WebContent任意读写
    ↓ 需要绕过PAC执行ROP
漏洞2 (JSC类型混淆) → 辅助PAC绕过
    ↓ 构造合法的签名跳转
漏洞3 (IOSurface) → 内核态攻击
    ↓ 内核PAC与用户态PAC不同密钥
漏洞4 (IOKit UAF) → 内核任意读写
    ↓ 在内核中操作时需要通过内核PAC
漏洞5 (内核提权) → 修改cred
    ↓ 控制流劫持需绕过内核CFI+PAC
漏洞6 (持久化) → 代码执行验证
```

### 5.2 ShadowCallStack与PAC的协同

iOS内核使用ShadowCallStack（SCS）与PAC协同保护返回地址：

```
正常调用：
  BL → 返回地址PAC签名 → 同时存入SCS区域
  RET → 从SCS读出 → AUT验证 → 跳转

攻击者面对：
  - 修改栈上的返回地址 → SCS不匹配
  - 修改SCS区域 → 需要知道SCS区域地址
  - 构造合法PAC → 密钥不可获取
  - 跳过AUT → 需要找到未保护的gadget

绕过策略（DarkSword采用）：
  - 信息泄露获取SCS区域地址
  - 内核UAF同时篡改SCS和PAC指针
  - 在SCS更新窗口期内完成替换
```

### 5.3 内核CFI的协同绕过

iOS内核使用Clang CFI（-fsanitize=cfi）保护间接调用：

```c
// 内核函数指针调用点（CFI保护后）
// 编译器插入的类型检查等价于：
if (funcptr->type_id != expected_type) {
    panic("CFI violation");
}
((void(*)(int))funcptr)(arg);
```

DarkSword中绕过CFI的方法：
- 寻找同类型签名的gadget（type confusion需要匹配签名）
- 通过任意写修改CFI检查表中的type_id字段
- 利用早期启动阶段CFI尚未初始化的窗口

---

## 第六章 PAC的局限性分析

### 6.1 密码学强度与实际安全的差距

16位PAC在理论上的安全性：
- 单次猜测成功率：1/65536
- 暴力尝试50000次 → 成功率约50%
- 但ARM实现中验证失败触发异常 → 进程终止
- 实际上：需要50000个子进程/线程尝试

iOS的缓解措施：
- 异常触发后记录审计日志
- 同一漏洞利用模式被检测后触发安全响应
- 但一次性利用（如Coruna的定向攻击）不受此影响

### 6.2 Modifier的可预测性

PAC安全性依赖于modifier的不可预测性。标准modifier是SP值：

```
理想情况：SP值随机化，攻击者不可预测
实际情况：
  - 函数调用栈深度在特定路径上固定
  - ASLR仅影响基址，不影响相对偏移
  - 如果攻击者泄露了一个栈地址 → 可推算SP
  - 某些代码路径使用常量modifier → 完全可预测
```

### 6.3 数据指针PAC的可选性

PACDA/PACDB（数据指针认证）在iOS中并非强制：

- 框架内部的对象引用（如NSArray中的指针）通常不签名
- 虚函数表指针（vtable）在部分实现中无PAC
- 函数指针存储在结构体中时PAC覆盖率不完整
- 攻击者通过修改数据指针绕过控制流检查

### 6.4 侧信道对PAC的威胁

PAC的密钥存储在系统寄存器中，但：

- 微架构侧信道（Spectre类）可能泄露密钥派生过程
- 功耗分析可以恢复密钥（理论可行，实际难执行）
- 时间侧信道：PAC验证失败的异常处理时间可能泄露信息

---

## 第七章 下一代控制流保护

### 7.1 BTI（Branch Target Identification）

ARMv8.5引入的BTI作为PAC的补充：

```
工作原理：
  - 间接跳转目标必须是 BTI 指令开始的位置
  - 页表中标记 BTI-enforced 页面
  - 间接分支到非BTI目标 → 触发异常

与PAC的关系：
  - BTI限制"能跳到哪里"（目标合法性）
  - PAC限制"指针是否被篡改"（来源完整性）
  - 两者正交互补

对ROP的影响：
  - gadget必须从BTI指令开始 → 大幅减少可用gadget
  - 与PAC联合使用 → 攻击者需同时满足两个约束
```

### 7.2 MTE（Memory Tagging Extension）

ARMv8.5 MTE通过内存标签检测UAF和缓冲区溢出：

```
原理：
  - 每个16字节内存块有一个4位Allocation Tag
  - 指针携带对应的Logical Tag
  - 访问时硬件比较两种Tag
  - 不匹配 → 同步/异步异常

对PAC绕过的协同效果：
  - 许多PAC绕过需要先获得任意读写能力
  - MTE检测UAF → 阻止任意读写原语的构造
  - 间接增加PAC绕过的难度

iOS部署现状：
  - A17 Pro芯片硬件支持
  - iOS 17+部分系统组件启用异步模式
  - 全面同步模式预计在iOS 18/19部署
```

### 7.3 SPTM对控制流保护的重定义

SPTM从根本上改变了控制流保护的信任模型：

```
传统模型：
  内核管理所有代码 → PAC保护内核代码完整性 → 但仍依赖内核自身
  
SPTM模型：
  每个World的代码页由SPTM管理
  TXM验证所有内核代码的CFI
  跨World的代码执行被SPTM物理阻断
  → PAC不再是唯一的控制流防线
  → 即使PAC被绕过，SPTM仍可阻止跨域执行
```

### 7.4 Formal PAC Verification

Apple研究团队探索的方向——对特定安全关键路径使用形式化方法证明PAC不变量：

- 证明不存在可触发PACia指令的可控路径
- 证明函数指针存储区域不被非签名写入
- 证明modifier值的熵在所有攻击者可见场景中充足

---

## 第八章 攻击者视角：PAC绕过的工程约束

### 8.1 实际攻击中的成本分析

从攻击工程角度，PAC绕过显著增加了开发成本：

```
无PAC环境：
  1. 获得任意读写 → 修改返回地址 → ROP → 完成
  开发时间：1-3天（熟练研究员）

有PAC环境（iOS ARM64e）：
  1. 获得任意读写
  2. 额外需要：
     - 寻找签名预言机（代码审计数周）
     - 或大量信息泄露收集签名对（开发复杂）
     - 或利用非PAC覆盖的间接跳转路径
  3. 每个利用步骤需要同时维护PAC一致性
  4. 在目标iOS版本更新后可能需要重新适配
  开发时间：数周到数月
  漏洞依赖：需要额外1-2个辅助漏洞
```

### 8.2 定向攻击 vs 批量利用

PAC的存在区分了两类攻击的可行性：

- **定向攻击（如Coruna）**：针对特定设备、特定iOS版本、有充分开发时间——PAC绕过是可控的工程挑战
- **批量攻击**：需要覆盖多设备/多版本——PAC绕过必须对每种配置单独适配，成本极高

这解释了为何PAC对"大规模监控"类攻击（需要跨版本通用利用）的防御效果显著优于对"定向间谍"的防御。

### 8.3 漏洞市场的影响

PAC增加了iOS漏洞利用链的开发难度，影响了漏洞市场：

```
影响链：
  PAC增加利用复杂度
  → 单个WebKit RCE不足以完成全链利用
  → 需要配合内核信息泄露 + 提权漏洞
  → 完整0-day利用链价值从$50K上升到$2-5M
  → 只有国家级APT和高级商业CSOP能承担
  → 普通犯罪活动转向钓鱼/社工/MFT攻击
```

---

## 第九章 防御者视角：PAC配置优化

### 9.1 最大化PAC覆盖率

对iOS开发者的建议：

```
编译选项：
  -mbranch-protection=pac-ret+b-key    ; 标准：返回地址用B密钥
  -fobjc-tagged-pointers=dyld          ; ObjC对象指针认证
  -fsanitize=cfi                       ; CFI与PAC协同

代码模式：
  ✓ 所有间接调用通过带签名的函数指针
  ✓ 回调注册时验证签名
  ✗ 避免将PAC指针存入可被非PAC路径修改的数据结构
  ✗ 避免在JIT区域附近分配敏感签名数据
```

### 9.2 检测异常PAC验证失败

运行时监控：

```c
// 内核中的PAC验证失败处理
void handle_pac_exception(struct exception_frame *frame) {
    // 增加异常计数
    increment_pac_failure_count(current_proc());
    
    // 如果短时间内大量PAC失败 → 可能是探测攻击
    if (recent_pac_failures > threshold) {
        // 终止进程 + 上报安全审计
        proc_signal(current_proc(), SIGKILL);
        audit_report_pac_attack(current_proc(), frame);
    }
    
    // 正常：终止当前进程
    proc_signal(current_proc(), SIGKILL);
}
```

### 9.3 密钥隔离最佳实践

- 进程创建时立即派生唯一EL0密钥
- 密钥在fork后必须重新派生
- 防止子进程继承父进程的签名预言机能力
- 高权限服务使用与标准进程不同的密钥体系

---

## 第十章 总结

PAC作为Apple ARM64e安全体系的核心组件，通过将密码学验证嵌入指针操作实现了硬件辅助的控制流完整性。Coruna和DarkSword的实际利用证明了：

1. **PAC不是银弹**：有足够漏洞辅助时，签名预言机和信息泄露可绕过PAC
2. **PAC改变攻击经济学**：使单漏洞利用不再足够，显著增加利用开发成本
3. **PAC与软件保护正交互补**：必须与CFI、SCS、MTE协同形成多层防线
4. **未来方向是架构隔离**：SPTM/TXM将控制流保护从"验证"升级为"物理不可能"

对安全研究员而言，PAC绕过技术代表了现代移动安全攻防的最前沿——理解PAC不仅是理解ARM架构，更是理解如何在硬件约束下寻找软件缺陷的创造性过程。

---

## 参考资源

- ARM Architecture Reference Manual (ARMv8.3 PAC Extension)
- QARMA5: A family of lightweight block ciphers for pointer authentication
- Apple Platform Security (2024): Pointer Authentication Codes
- Coruna Technical Details - Google TAG / Lookout (2024)
- DarkSword: Six Vulnerabilities Analysis - Meta/Google TAG (2025)
- "Pointer Incontext Authentication" - USENIX Security (2024)
- iOS Kernel PAC Bypass Research - Pangu Team / XK7 (2025)
