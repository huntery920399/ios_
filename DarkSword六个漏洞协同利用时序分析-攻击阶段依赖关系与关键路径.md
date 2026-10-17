# DarkSword六个漏洞协同利用时序分析：攻击阶段依赖关系与关键路径

## 摘要

DarkSword利用6个不同的漏洞完成从浏览器上下文到内核权限的完整攻击链。这些漏洞并非独立使用，而是按照严格的时序依赖关系协同工作。本文深入分析DarkSword的漏洞利用时序，揭示各阶段之间的依赖关系、关键路径以及失败处理机制。

## 一、DarkSword漏洞利用全景

### 1.1 漏洞清单

```text
DarkSword漏洞利用时序：

阶段1：WebKit入口（JavaScriptCore）
├─ CVE-2025-31277：JIT类型混淆
└─ CVE-2025-43529：GC相关缺陷

阶段2：沙箱逃逸
└─ CVE-2025-43510：XNU copy-on-write漏洞

阶段3：权限提升
├─ CVE-2025-43520：XNU VFS竞态条件
└─ 其他2个漏洞（未公开详细CVE）

阶段4：载荷执行
└─ JavaScript-based payload
```

### 1.2 攻击流程图

```text
完整攻击流程：

用户访问恶意网页
    │
    ▼
[1] CVE-2025-31277 触发
    │  JIT类型混淆
    │  获得初始代码执行
    ▼
[2] CVE-2025-43529 利用
    │  GC缺陷
    │  增强内存控制能力
    ▼
[3] 构建内存读写primitives
    │  read64/write64
    │  任意地址访问
    ▼
[4] CVE-2025-43510 利用
    │  XNU copy-on-write
    │  在mediaplaybackd中建立能力
    ▼
[5] 沙箱逃逸完成
    │  突破WebContent沙箱
    │  获得更广泛的系统访问
    ▼
[6] CVE-2025-43520 利用
    │  XNU VFS竞态条件
    │  建立内核读写能力
    ▼
[7] 权限提升完成
    │  获得内核权限
    │  完全控制设备
    ▼
[8] JavaScript payload执行
    │  数据收集
    │  外传到C2
    ▼
攻击完成
```

## 二、阶段1：WebKit入口（CVE-2025-31277）

### 2.1 漏洞原理

CVE-2025-31277是JavaScriptCore JIT编译器中的类型混淆漏洞。

```javascript
// 概念代码：触发类型混淆

function triggerTypeConfusion() {
    // 1. 创建一个数组
    let arr = [1.1, 2.2, 3.3];
    
    // 2. 通过prototype污染改变数组元素类型
    Array.prototype.__defineGetter__(0, function() {
        return {valueOf: () => "string"};
    });
    
    // 3. JIT编译器优化时假设arr[0]是double
    // 但实际返回的是对象
    function optimize(arr) {
        // JIT假设arr[0]是double，生成优化代码
        let sum = 0;
        for (let i = 0; i < arr.length; i++) {
            sum += arr[i]; // 类型混淆发生在这里
        }
        return sum;
    }
    
    // 4. 触发JIT编译
    for (let i = 0; i < 10000; i++) {
        optimize(arr);
    }
    
    // 5. 此时arr[0]被误解为double，但实际是对象指针
    // 攻击者可以通过这个混淆读取对象内存
    let confused = optimize(arr);
    
    return confused;
}
```

### 2.2 利用目标

```text
阶段1目标：

✓ 在WebContent进程中获得代码执行
✓ 建立初步的内存读取能力
✓ 为阶段2奠定基础

✗ 不需要绕过沙箱
✗ 不需要内核权限
✗ 不需要持久化
```

### 2.3 失败处理

```text
如果阶段1失败：

情况A：漏洞不存在（已修复）
→ 静默退出
→ 不尝试后续阶段

情况B：利用不稳定（崩溃）
→ 捕获异常
→ 清理痕迹
→ 等待下次机会

情况C：环境检测失败（锁定模式等）
→ 不触发漏洞
→ 避免崩溃
→ 记录环境信息
```

## 三、阶段2：内存控制增强（CVE-2025-43529）

### 3.1 漏洞原理

CVE-2025-43529涉及JavaScriptCore垃圾回收机制的缺陷。

```javascript
// 概念代码：利用GC缺陷

function exploitGCDefect() {
    // 1. 创建大量对象，触发GC
    let objects = [];
    for (let i = 0; i < 10000; i++) {
        objects.push({data: new Array(1000)});
    }
    
    // 2. 释放部分对象，制造内存空洞
    objects = objects.slice(0, 5000);
    
    // 3. 在GC过程中，利用缺陷控制内存布局
    // GC移动对象时，攻击者可以预测新地址
    let controlled = allocateAtPredictableLocation();
    
    // 4. 现在攻击者知道controlled对象的精确地址
    // 可以构建更强大的内存读写primitives
    
    return controlled;
}
```

### 3.2 与阶段1的依赖

```text
依赖关系：

阶段1 → 阶段2：

1. 阶段1提供初始代码执行
   └─ 没有代码执行，无法触发GC缺陷
   
2. 阶段1建立初步内存读取
   └─ 用于验证GC缺陷利用成功
   
3. 阶段1绕过初步缓解措施
   └─ 为阶段2创造条件

关键依赖：
✓ 阶段1必须成功
✓ 阶段1的内存读取能力必须稳定
✓ 阶段1不能导致崩溃
```

### 3.3 利用目标

```text
阶段2目标：

✓ 精确控制内存布局
✓ 构建强大的读写primitives
✓ 为沙箱逃逸做准备

read64(addr)：
- 读取任意地址的64位值
- 用于绕过ASLR
- 用于读取内核数据结构

write64(addr, value)：
- 写入任意地址
- 用于修改内核数据结构
- 用于劫持控制流
```

## 四、阶段3：沙箱逃逸（CVE-2025-43510）

### 4.1 漏洞原理

CVE-2025-43510是XNU内核中copy-on-write机制的漏洞。

```text
Copy-on-Write机制：

正常流程：
1. 进程A和进程B共享同一物理页面
2. 两个进程的虚拟地址映射到同一物理页面
3. 当任一进程写入时，触发COW
4. 内核复制物理页面
5. 更新写入进程的页表

漏洞利用：
1. 攻击者控制写入时机
2. 在COW过程中制造竞态条件
3. 绕过COW保护
4. 直接修改共享页面
5. 影响其他进程
```

### 4.2 在mediaplaybackd中建立能力

```javascript
// 概念代码

function exploitCOWInMediaplaybackd() {
    // 1. 找到mediaplaybackd进程的内存
    let mediaPid = findProcess("mediaplaybackd");
    
    // 2. 利用COW漏洞，修改mediaplaybackd的内存
    // 由于COW缺陷，可以直接修改共享页面
    
    // 3. 在mediaplaybackd中注入代码
    let injectedCode = `
        // 这段代码在mediaplaybackd进程中执行
        // mediaplaybackd的沙箱权限比WebContent更高
        // 可以访问更多系统资源
    `;
    
    injectIntoProcess(mediaPid, injectedCode);
    
    // 4. 现在攻击者拥有两个进程的控制权
    // - WebContent（受限）
    // - mediaplaybackd（更宽松）
    
    return {
        webcontent: getCurrentProcess(),
        mediaplaybackd: mediaPid
    };
}
```

### 4.3 沙箱逃逸的意义

```text
沙箱逃逸后的能力提升：

WebContent沙箱：
✗ 无法访问用户数据
✗ 无法访问文件系统
✗ 网络访问受限
✗ IPC调用受限

mediaplaybackd权限：
✓ 可以访问媒体文件
✓ 可以访问部分系统服务
✓ 网络访问更宽松
✓ 可以调用更多IPC接口

攻击者现在可以：
- 读取用户照片、视频
- 访问部分应用数据
- 建立更广泛的系统访问
- 为内核提权做准备
```

## 五、阶段4：内核提权（CVE-2025-43520）

### 5.1 漏洞原理

CVE-2025-43520是XNU虚拟文件系统（VFS）中的竞态条件漏洞。

```text
VFS竞态条件：

正常流程：
1. 进程请求打开文件
2. VFS检查权限
3. 权限检查通过
4. 返回文件描述符

竞态条件：
1. 攻击者创建特殊文件
2. 在权限检查和文件打开之间
3. 替换文件为符号链接
4. 指向受保护的文件
5. 获得未授权的访问

利用场景：
- 读取受保护的系统文件
- 修改内核数据结构
- 提升进程权限
```

### 5.2 建立内核读写能力

```javascript
// 概念代码

function exploitVFSRaceCondition() {
    // 1. 创建竞态条件
    let raceWindow = createRaceWindow();
    
    // 2. 在竞态窗口中，替换文件为符号链接
    let symlink = createSymlinkToKernelMemory();
    
    // 3. 通过VFS漏洞，获得内核内存的访问
    let kernelAccess = openThroughRace(raceWindow, symlink);
    
    // 4. 现在可以读写内核内存
    // 建立内核级别的primitives
    
    let kernelRead = (addr) => {
        return readFromKernelMemory(kernelAccess, addr);
    };
    
    let kernelWrite = (addr, value) => {
        return writeToKernelMemory(kernelAccess, addr, value);
    };
    
    return {kernelRead, kernelWrite};
}
```

### 5.3 内核提权的完成

```text
内核提权后的能力：

✓ 完全控制设备
✓ 访问所有用户数据
✓ 修改系统配置
✓ 安装持久化后门
✓ 隐藏攻击痕迹

具体操作：
1. 修改进程凭证
   - 将当前进程提升为root
   
2. 绕过代码签名
   - 修改amfid配置
   - 允许执行未签名代码
   
3. 安装持久化
   - 创建LaunchDaemon
   - 修改系统启动流程
   
4. 清理痕迹
   - 删除日志
   - 隐藏文件
   - 伪装进程
```

## 六、漏洞依赖关系图

### 6.1 关键路径分析

```text
关键路径（Critical Path）：

CVE-2025-31277 → CVE-2025-43529 → CVE-2025-43510 → CVE-2025-43520

这是攻击链的核心路径，任何一个环节失败，整个攻击链就会中断。

非关键路径：

其他2个漏洞可能是：
- 备用路径（如果主路径失败）
- 辅助功能（增强稳定性）
- 特定场景（适配不同设备）
```

### 6.2 依赖矩阵

```text
漏洞依赖矩阵：

           31277  43529  43510  43520  其他
31277      -      ✓      ✓      ✓      ?
43529             -      ✓      ✓      ?
43510                    -      ✓      ?
43520                           -      ?
其他                                  -

✓ = 强依赖（必须成功）
? = 可能依赖（根据场景）
```

### 6.3 时序约束

```text
时序约束：

1. 严格顺序
   31277 → 43529 → 43510 → 43520
   
   不能并行执行
   不能调换顺序
   
2. 时间窗口
   某些漏洞利用有时间窗口
   必须在特定时间内完成
   
3. 状态依赖
   后续漏洞依赖前序漏洞建立的状态
   状态丢失会导致失败
```

## 七、失败处理与恢复

### 7.1 阶段失败处理

```text
阶段1失败（CVE-2025-31277）：

原因：
- 漏洞已修复
- 环境不适合（锁定模式）
- 利用不稳定

处理：
- 静默退出
- 不尝试后续阶段
- 清理痕迹

阶段2失败（CVE-2025-43529）：

原因：
- 内存布局不符合预期
- GC行为异常
- 竞态条件未触发

处理：
- 重试有限次数（3次）
- 如果仍然失败，退出
- 避免崩溃

阶段3失败（CVE-2025-43510）：

原因：
- COW机制已修复
- mediaplaybackd不可用
- 沙箱配置变化

处理：
- 尝试备用沙箱逃逸方法
- 如果所有方法失败，退出
- 保留已获得的WebContent能力

阶段4失败（CVE-2025-43520）：

原因：
- VFS漏洞已修复
- 竞态窗口太短
- 内核数据结构变化

处理：
- 这是最后阶段
- 失败意味着无法获得内核权限
- 可能退化为部分能力（沙箱内）
```

### 7.2 崩溃恢复

```text
崩溃恢复策略：

1. 预防崩溃
   - 充分的测试和验证
   - 优雅的错误处理
   - 避免不稳定的操作
   
2. 崩溃检测
   - 监控进程状态
   - 检测异常行为
   - 捕获异常信号
   
3. 崩溃恢复
   - 如果WebContent崩溃
     → 用户可能重新打开页面
     → 重新尝试攻击
   
   - 如果系统服务崩溃
     → 可能引起用户注意
     → 清理痕迹，退出
```

## 八、防御启示

### 8.1 破坏关键路径

```text
防御策略：

1. 修复关键漏洞
   - CVE-2025-31277（已在iOS 26.3修复）
   - CVE-2025-43529（已在iOS 26.3修复）
   - 破坏攻击链的关键路径
   
2. 加强缓解措施
   - 更严格的类型检查
   - 更安全的GC机制
   - 更可靠的COW实现
   
3. 纵深防御
   - 不依赖单一安全边界
   - 多层防护机制
   - 即使一层被突破，还有其他层
```

### 8.2 检测攻击行为

```text
检测指标：

阶段1检测：
- 异常的JavaScript执行模式
- 大量的JIT编译活动
- 异常的内存分配

阶段2检测：
- 异常的GC行为
- 大量的对象创建和销毁
- 内存布局异常

阶段3检测：
- 跨进程异常行为
- mediaplaybackd异常
- IPC调用异常

阶段4检测：
- VFS操作异常
- 文件系统竞态条件
- 内核数据结构异常访问
```

## 九、结论

DarkSword的6个漏洞协同利用展示了现代iOS攻击链的复杂性。关键发现：

1. **严格的时序依赖** — 漏洞必须按照特定顺序执行，不能并行或调换
2. **关键路径明确** — CVE-2025-31277 → 43529 → 43510 → 43520是核心路径
3. **失败处理精细** — 每个阶段都有明确的失败处理策略
4. **状态依赖强** — 后续阶段依赖前序阶段建立的状态

对于防御：

1. 修复任何一个关键漏洞都可以破坏整个攻击链
2. 需要关注漏洞之间的协同效应
3. 纵深防御比单点防护更有效
4. 运行时检测可以发现攻击行为

DarkSword的攻击链设计为安全研究提供了宝贵的案例，帮助理解高级攻击技术的实现细节和防御方法。
