# iOS代码签名体系攻防演进——从AMFI到内核签名验证的突破与加固

## 摘要

代码签名机制是iOS安全模型的信任根之一。从应用安装、进程创建、动态库加载到内核模块验证，iOS通过多层签名检查确保只有Apple认可或用户显式授权的代码才能执行。然而Coruna与DarkSword等高级攻击展示了多种签名绕过策略。本文从签名体系架构、证书链信任模型、AMFI强制机制、内核验证路径四个维度展开分析，并探讨签名保护在下一代iOS安全架构中的角色演变。

---

## 第一章 iOS代码签名体系架构

### 1.1 签名的层次结构

iOS的代码签名不是单一检查点，而是贯穿整个软件生命周期的多层验证体系：

```
层次1：发布签名（App Store / Developer ID）
  - Apple开发者证书签名IPA
  - 提交时Apple服务器验证并重新签名
  - 安装时设备验证Apple签名

层次2：运行时签名（AMFI / cs_validate）
  - 进程加载时验证代码段哈希
  - 动态库加载时验证每页完整性
  - 代码页从磁盘加载时触发按需验证

层次3：内核签名（内核扩展 / driverkit）
  - 内核代码在启动时由Secure Boot链验证
  - 运行时加载的kext需要Apple签名授权
  - DriverKit驱动独立签名体系

层次4：硬件信任根（SEP / Secure Boot）
  - Boot ROM固化Apple公钥哈希
  - 逐级验证Bootloader → Kernel → Launchd
  - 签名密钥在SE熵源中绑定设备唯一性
```

### 1.2 Mach-O签名结构

iOS可执行文件（Mach-O格式）的签名嵌入在特定LC中：

```
LC_CODE_SIGNATURE → 包含：
  ├── SuperBlob
  │   ├── CodeDirectory (main binary)
  │   │   ├── Hash pages (4096 bytes per hash)
  │   │   ├── Team ID
  │   │   ├── Entitlements hash
  │   │   └── Flags (runtime hardening等)
  │   ├── Entitlements blob
  │   ├── Requirements blob (指定签名者条件)
  │   └── Embedded CodeDirectory (子组件)
  ├── Signature (CMS/PKCS7格式)
  │   ├── Apple CA证书链
  │   └── 开发者证书
  └── Timestamp (可选)
```

关键设计：
- **Hash Tree（Merkle-like）**：代码页被逐页哈希，任何修改导致哈希不匹配
- **Entitlements**：签名中包含的权限声明（如keychain-access-groups、get-task-allow）
- **Requirements**：指定"谁必须签过名"——可以是特定的Apple证书

### 1.3 签名与页面级别的绑定

iOS对代码页的验证是按需（page-in）触发的：

```
流程：
  CPU取指 → 页面不在内存 → Page Fault
  → 内核pager拦截
  → 检查页面是否属于已签名代码
  → 从签名CodeDirectory中取出预期哈希
  → 计算实际页面哈希对比
  → 不匹配 → SIGKILL进程
  
  匹配 → 页表标记为执行权限 → 继续执行
```

这意味着：攻击者修改内存中的代码页不会生效——因为下次page-in会重新从磁盘加载并验证。但一旦页面已在内存中（已验证），除非被主动逐出，后续执行不会再检查。

---

## 第二章 AMFI与CSM（Code Signing Monitor）

### 2.1 AMFI守护进程的角色

AMFI（Apple Mobile File Integrity）是iOS中管理代码签名策略的核心组件：

```c
// AMFI内核扩展的关键职责（amfi.kext）

// 1. 页面验证钩子
int amfi_check_page(
    proc_t p,
    csm_object_t obj,      // 签名对象
    vm_object_t vmo,       // 虚拟内存对象
    vm_page_t page,        // 要验证的页面
    ...
);

// 2. 动态库验证
int amfi_check_dyld_policy_self(
    cdhash_t hash,         // 待加载库的CDHash
    ...
);

// 3. 内核签名强制开关
boolean_t amfi_get_boot_constraint(...);  // 读取安全启动约束
```

### 2.2 CSValidate执行路径

每次涉及代码页加载或执行时，内核调用cs_validate：

```
cs_validate流程：
  1. 获取签名信息（从inode的XATTR中或缓存中）
  2. 计算目标页面哈希（SHA-256）
  3. 与CodeDirectory中记录的哈希对比
  4. 验证签名Blob完整性（从CD到最终证书）
  5. 检查Entitlements是否允许该操作
  6. 检查是否命中黑名单（Apple实时推送的CSReq黑名单）

失败结果：
  → 代码页被标记为不可信
  → 进程收到CS_KILL信号
  → 记录审计日志
```

### 2.3 内核中的签名强制点

```
强制点列表：

execve()路径：
  → 检查目标二进制签名
  → 验证Entitlements与进程继承权限的兼容性
  → 检查hardened runtime标志

dlopen()路径：
  → 动态库必须在主二进制签名中声明为可加载
  → 或位于Apple系统路径（有独立Apple签名）
  → 或来自同Team ID的嵌入框架

mmap(PROT_EXEC)路径：
  → 映射的代码页必须有合法签名
  → 匿名可执行映射被禁止（JIT例外通过特殊路径）

mprotect(PROT_EXEC)路径：
  → 修改已有映射为可执行
  → 触发签名重新验证
  → W^X规则：可写页不可同时可执行
```

### 2.4 DYLD共享缓存与签名

iOS系统将大量系统框架预链接为dyld_shared_cache：

```
设计：
  - 数百个系统框架/库被合并为单一文件
  - 整体签名一次（避免每库单独验证的开销）
  - 运行时直接映射共享缓存页面

安全含义：
  - 修改共享缓存中任何内容都导致整体签名失败
  - 但一旦缓存加载到内存并被验证，
    后续通过内存写入修改其中的数据
    → 需要同时绕过PAC + 内存保护 + MIE（如果可用）

攻击面：
  - 如果缓存页面在验证后变为可写（如调试场景），
    修改缓存中的函数实现将影响所有使用该函数的进程
```

---

## 第三章 Coruna攻击中的签名绕过

### 3.1 JIT区域与签名豁免

Coruna利用WebContent进程中的JIT区域来绕过部分签名检查：

```
JIT页面的特殊处理：
  1. JavaScriptCore分配RWX映射区域（通过特殊内核通道）
  2. JIT写入的机器码不经过cs_validate（无磁盘签名）
  3. 替代保护：PAC验证间接跳转 + W^X分离

Coruna的利用方式：
  - 通过JIT漏洞注入攻击代码到JIT页面
  - 该页面已标记为可执行且无签名要求
  - 但跳转到JIT页面外仍需PAC认证
  
  → 签名系统被绕过了，但PAC仍然有效
  → 攻击者需要额外的PAC绕过才能逃逸JIT区域
```

### 3.2 页面重用攻击

```
场景：
  1. 合法页面P被加载并验证 → 标记为可信可执行
  2. 攻击者触发P被逐出（memory pressure）
  3. 同一物理页帧被分配给其他用途
  4. 攻击者修改该物理页内容
  5. P再次page-in → 但内核缓存了验证结果？

Apple的缓解：
  - 页帧重用前清零（或至少清除执行标记）
  - 验证缓存与页对象绑定而非物理帧
  - 但历史版本中存在缓存失效不完全的案例
```

### 3.3 CSFlag操纵

每个VM对象有csflags（代码签名标志），标记其验证状态：

```
CS_OSSignatureStatus:
  CS_OSS_NEW_ENFORCED   = 已强制新策略
  CS_OSS_HARD           = 严格模式（无容错）
  CS_OSS_KILLED         = 已验证失败，进程应终止
  CS_OSS_INVALID        = 签名无效

攻击思路：
  如果获得任意内核读写后修改CSFlags
  将CS_OSS_INVALID改为CS_OSS_NEW_ENFORCED
  → 内核认为该页面已验证通过
  → 跳过后续签名检查
```

---

## 第四章 DarkSword的签名绕过策略

### 4.1 内核代码签名与动态加载

iOS内核代码在启动时通过以下信任链验证：

```
Boot ROM → iBoot → KernelCache → kextd

攻击者不能加载未签名的内核代码。
但DarkSword绕过签名限制的方式：
  → 不加载新代码，而是修改已有合法代码的行为
  → 利用ROP在已签名的内核代码段中执行
  → 修改函数指针/数据结构改变执行路径
  → 所有执行都在合法签名的代码中进行

关键洞察：签名验证的是"代码是否被修改"，
而非"代码执行了什么操作"。
合法代码被误用（confused deputy）不触发签名告警。
```

### 4.2 代码页写保护的绕过

```
iOS中的W^X实现：
  - 代码页映射后标记为 RO+X（只读可执行）
  - 数据页标记为 RW-（可写不可执行）
  - 同时设置两者被SPTM/PTE保护阻止

DarkSword的绕过场景：
  - 通过内核任意读写修改页表项
  - 将目标代码页的PTE从RO+X改为RW+X
  - 写入shellcode后再改回RO+X
  - 执行修改后的代码 → 页面哈希已改变

  为什么不被检测：
  - cs_validate仅在page-in时触发
  - 页面已在内存中 → 不重新验证
  - 页表修改本身不触发签名重新检查
```

### 4.3 DYLD注入攻击的演变

传统DYLD注入（如DYLD_INSERT_LIBRARIES）在iOS上被完全禁止。但更隐蔽的注入技术仍然存在：

```
iOS上的合法库加载：
  1. 主二进制声明的@rpath路径
  2. 嵌入框架（Frameworks/目录）
  3. 系统dyld共享缓存中的库

攻击注入方式（假设已有任意读写）：
  - 修改进程的mach_header中dyld_info结构
  - 改变LC_LOAD_DYLIB条目指向恶意库
  - 但dyld自身代码段已签名 → 修改内存中的dyld行为困难
  - 更实际：修改已加载库的GOT（全局偏移表）条目
    → 重定向函数调用到攻击者代码
    → 需要GOT页面可写（RELRO保护已普遍部署）
```

---

## 第五章 签名验证的硬件根信任

### 5.1 Secure Boot Chain

代码签名的最终信任来自硬件：

```
┌──────────────────────────────────────────┐
│ Boot ROM (掩膜ROM，不可修改)              │
│   固化Apple根公钥哈希                     │
├──────────────────────────────────────────┤
│ iBoot (验证后才执行)                      │
│   Apple签名 → Boot ROM验证               │
│   版本锁定（SEP中ANTI-REPLAY计数器）      │
├──────────────────────────────────────────┤
│ KernelCache                               │
│   Apple签名 → iBoot验证                   │
│   SEP辅助验证（防中间人篡改）             │
├──────────────────────────────────────────┤
│ launchd / 系统进程                         │
│   Apple签名 → 内核AMFI验证                │
└──────────────────────────────────────────┘

SEP的角色：
  - 存储根公钥（不可通过软件修改）
  - 参与Boot链验证的nonce生成（防回滚）
  - 密钥绑定设备UID → 签名材料不可跨设备复用
```

### 5.2 Secure Enclave与签名验证的协同

SEP不仅保护生物识别数据，还参与系统级签名验证：

```
场景1：OTA更新验证
  - 更新包由Apple签名
  - 设备端用SEP中的公钥验证
  - nonce确保不可降级到旧版本

场景2：运行时代码签名黑名单
  - Apple通过CRL推送已泄露/撤销的开发者证书
  - 设备端AMFI检查签名时查询黑名单
  - 黑名单条目由SEP密封保护（防本地篡改）

场景3：内核完整性监控
  - SEP定期验证内核关键结构的哈希
  - 异常变更触发安全模式（限制功能）
```

### 5.3 密钥隔离与设备绑定

iOS代码签名的一个关键设计：

- App Store应用的签名密钥在分发时由Apple替换
- 开发者证书无法直接签名为可安装IPA
- 每个二进制与设备UDID绑定（开发签名场景）
- 企业证书签名的应用可通过配置描述符安装
- 越狱绕过：修改设备UDID验证/替换证书链

---

## 第六章 签名绕过检测技术

### 6.1 内核完整性监控

```
macOS/iOS内置的完整性监控机制：
  1. Kernel Integrity Protection (KIP)
     - 监控内核代码段是否被修改
     - 基于哈希对比（非签名验证，而是运行时监控）
     
  2. 页面哈希采样
     - 内核定时器随机选取代码页重新计算哈希
     - 不匹配 → 触发panic → 记录崩溃日志
     
  3. IOKit完整性
     - 驱动代码段定期验证
     - 修改检测 → 标记进程为不可信
```

### 6.2 行为级检测

```
高置信绕过指标（SOC层面）：
  - 进程加载了非签名映射的代码页（JIT除外）
  - 代码段执行后哈希变化（page hash mismatch）
  - 未授权的dyld加载事件
  - 系统调用序列中出现签名验证跳过模式
  
设备级检测（MDM/安全产品）：
  - 启动时验证系统完整性（root of trust链）
  - 定期检查关键系统二进制的CDHash
  - 监控AMFI日志中的拒绝事件
```

### 6.3 崩溃日志中的签名异常

```
iOS崩溃日志（.ips文件）中的签名问题指标：
  - "Code Signature Invalid" 异常类型
  - "AMFI" 相关子系统标识
  - csflags值显示异常状态
  - 进程被终止时的termination reason字段

安全分析价值：
  批量收集崩溃日志可以发现
  针对签名系统的攻击尝试模式
  （即使攻击未完全成功，
   验证失败事件本身就是攻击信号）
```

---

## 第七章 下一代签名架构

### 7.1 SPTM与签名强制的关系

```
SPTM如何增强代码签名：

传统模型：
  页表由内核管理 → 内核可修改PTE权限
  → 如果内核被攻破 → 可伪造页表绕过签名验证
  → 代码页可被标记为可写 → 修改内容 → 改回可执行

SPTM模型：
  页表由SPTM管理 → 内核只能请求SPTM修改
  → SPTM验证请求的合法性
  → 不允许将已签名的代码页改为可写
  → 即便内核代码被攻破 → 无法篡改签名代码页权限

  签名强制执行从"软件策略"升级为"硬件不可违反"
```

### 7.2 MIE对签名保护的补充

Memory Integrity Enforcement从另一个维度加固签名：

- MIE维护独立的内存使用元数据
- 代码页被标记为"合法代码"，非授权写入导致MIE违规
- 即使攻击者找到未受页表保护的修改路径，MIE仍可检测
- 对DarkSword类型的"修改页表属性后写入代码"攻击形成硬件阻断

### 7.3 TXM对关键验证逻辑的保护

```
TXM（Trusted Execution Monitor）：
  将系统中最关键的信任根操作隔离到独立安全世界

  可能纳入TXM的签名相关操作：
  - Boot链验证逻辑
  - 代码签名密钥管理
  - AMFI策略决策引擎
  - 黑名单更新和查询
  
  效果：
  即使主内核（XNU）被完全攻破，
  TXM仍在独立安全域中执行签名验证
  → 内核攻击者无法绕过TXM中的签名策略
```

### 7.4 远程证明（Remote Attestation）

未来iOS可能引入更完善的远程证明机制：

```
流程：
  设备 → 生成设备状态报告（启动链、签名状态、安全配置）
  → 用SEP中的设备密钥签名
  → 发送到Apple/企业服务器验证
  
价值：
  - 服务端可检测"已越狱"设备（即使本地隐藏了攻击痕迹）
  - 企业MDM可基于设备完整性状态实施访问控制
  - 金融类App可验证运行环境的代码签名完整性
  
对攻击者的意义：
  - 即使成功绕过了本地签名验证
  - 远程证明可能暴露篡改事实
  - 攻击必须同时对本地和远程验证层不可见
```

---

## 第八章 开发者视角：签名合规实践

### 8.1 Entitlements配置

```xml
<!-- 安全的Entitlements配置原则 -->
<plist>
<dict>
    <!-- 仅申请必需的entitlements -->
    <!-- ❌ 避免: com.apple.security.get-task-allow -->
    <!-- 此权限允许调试器附加，可能被利用 -->
    
    <!-- ✅ 限制keychain访问组到必要范围 -->
    <key>keychain-access-groups</key>
    <array>
        <string>$(AppIdentifierPrefix)com.myapp.specific</string>
    </array>
    
    <!-- ✅ 使用应用组时限制共享范围 -->
    <key>com.apple.security.application-groups</key>
    <array>
        <string>group.com.myapp.internal</string>
    </array>
</dict>
</plist>
```

### 8.2 Hardened Runtime配置

macOS应用的Hardened Runtime选项（iOS 17+类似策略扩展）：

- 禁止未签名可执行内存
- 库验证（仅加载同签名或Apple签名的库）
- 禁止调试器附加
- 禁止Apple事件（除非显式授权）
- 禁止 DYLD环境变量注入

### 8.3 安全更新流程

```
Apple安全更新流程：
  1. 发现漏洞 → 内部修复
  2. 新版本签名发布
  3. 旧证书/CDHash加入黑名单
  4. 设备端AMFI在线检查黑名单
  5. 已安装旧版本仍可运行（不强制更新）
  
开发者应注意：
  - 使用Apple推荐的安全区域设置Entitlements
  - 定期更新开发证书（避免证书泄露风险）
  - 不在生产构建中包含get-task-allow
  - 使用CI/CD中的安全签名流程（密钥不暴露于构建环境）
```

---

## 第九章 签名体系面临的核心挑战

### 9.1 "验证时态"问题

签名验证的核心难题是**验证时机与执行时机不匹配**：

```
验证发生在page-in时
执行发生在page命中TLB时
修改可以在验证之后执行之前

窗口期：
  [页面验证通过] → [页面在内存中] → [攻击者修改页面] → [执行修改后代码]
  
  只要页面不被逐出，签名验证结果被视为有效
  → 运行时篡改在已加载页面中可能不被检测
```

Apple的应对：
- 代码页通常映射为RO，修改需要额外突破
- 定期完整性采样（KIP）
- SPTM/MIE将从硬件消除这个窗口

### 9.2 JIT例外路径

```
代码签名与JIT的冲突：
  - JIT生成的代码无法预先签名
  - 但JIT是Web浏览器/App Store应用的核心能力
  - 需要信任边界：谁的JIT代码可信？
  
当前解决方案：
  - 只有特定进程（有dynamic-codesigning entitlement）可创建JIT
  - JIT页面受特殊内核管理（不可从普通路径写入）
  - JIT执行区域受PAC保护间接跳转
  
未来方向：
  - JIT代码页参与MIE验证（硬件追踪代码生成行为）
  - 基于形式化的JIT输出验证（不依赖签名）
```

### 9.3 性能与安全的平衡

```
逐页验证的性能开销：
  - SHA-256：每页4KB → 数百周期
  - 大型App首次加载：数百页 → 毫秒级延迟
  - 缓存机制：验证结果缓存在VM对象中
  - 批量验证：多页同时检查减少调用次数

Apple的优化策略：
  - 页面哈希结果缓存在页表属性中
  - 验证与页面预取并行执行
  - TLB shootdown仅在页面被标记为需要重验证时触发
```

---

## 第十章 总结

iOS代码签名体系从硬件信任根到运行时验证构建了完整的代码完整性保障链。Coruna和DarkSword的攻击实践揭示了：

1. **签名验证的时态缺陷**：已验证页面在内存中的保护依赖W^X和页表权限，而非持续哈希检查
2. **JIT路径的例外性**：动态代码生成是签名体系的必然豁免区，需要其他机制（PAC、W^X）补位
3. **合法代码的误用不可检测**：签名验证只保证代码完整性，不保证代码使用方式正确（ROP利用合法签名代码）
4. **硬件强制是最终答案**：SPTM/MIE/TXM将签名执行从"软件可以绕过的策略"升级为"物理上不可能违反的约束"

代码签名在iOS安全模型中的角色正从"主要防线"转变为"纵深防御的基础层"——它仍然是必要的，但已不足以单独防御高级攻击。

---

## 参考资源

- Apple Platform Security: Code Signing Enforcement (2024-2026)
- Mach-O Binary Format: Code Signature Structure
- XNU Source: bsd/kern/code_signing.c
- AMFI Technical Details - various jailbreak community analyses
- Coruna Exploitation Chain - Google TAG (2024)
- DarkSword: Multi-Vulnerability Exploit Analysis - Meta (2025)
- iOS JIT and Dynamic Code Generation Security - Apple Security Engineering
