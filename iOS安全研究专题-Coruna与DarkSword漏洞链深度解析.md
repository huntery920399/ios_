# iOS安全研究专题：Coruna与DarkSword漏洞链深度解析

**Coruna和DarkSword不是两个单独的漏洞，而是两套针对iPhone的高级漏洞利用工具包（Exploit Kit）。** 它们通过组合WebKit、JavaScriptCore、沙盒逃逸、PAC绕过及XNU内核漏洞，实现从浏览器代码执行到内核权限提升的多阶段攻击。

两者尤其值得结合前面讨论的 SPTM、TXM、PPL、XNU与Exclaves安全架构进行分析。

## 一、Coruna与DarkSword核心区别

**Coruna：** 23 漏洞利用模块，5条完整攻击链，iOS 13.0–17.2.1

**DarkSword：** 6 涉及6个CVE漏洞，iOS 18.4–18.7

版本范围为研究人员观察到的攻击工具适用范围，不代表范围内每个系统构建都必然可被同一攻击链利用。

| 比较项目 | Coruna | DarkSword |
|---------|--------|-----------|
| 公开披露 | 2026年3月3日 | 2026年3月18日 |
| 主要入口 | WebKit网页攻击 | JavaScriptCore网页攻击 |
| 内核攻击 | 多套内核漏洞利用 | XNU内核漏洞组合 |
| 内存保护绕过 | 包含PPL绕过技术 | 不依赖传统PPL/SPTM绕过来执行未签名原生代码 |
| 攻击实现 | JavaScript与原生利用组件 | 主要采用JavaScript实现 |
| 主要威胁 | 设备控制、间谍活动、加密资产盗取 | 数据窃取、监控、内核权限提升 |

资料来源：Google Threat Intelligence Group的两篇原始研究报告。

## 二、Coruna：针对iOS 13–17的完整漏洞利用框架

Coruna最值得关注的技术特点，是其并非只依赖一个Kernel Exploit，而是提供多条适配不同iOS版本的完整攻击链。

```
恶意或被入侵的网页
    Watering Hole / Web Delivery
        ↓
WebKit远程代码执行
    获取浏览器进程内代码执行能力
        ↓
PAC绕过与沙盒逃逸
    突破浏览器进程限制
        ↓
XNU内核权限提升
    利用内核漏洞扩大权限
        ↓
PPL保护绕过
    针对特定版本的内存保护机制
        ↓
恶意载荷执行
    数据收集与窃取
```

Google披露，Coruna的部分攻击链包含此前未公开的缓解机制绕过技术，并且先后被商业监控相关操作者、疑似国家背景攻击组织及经济利益驱动的犯罪团伙使用。

### Coruna与PPL的关系

PPL（Page Protection Layer）是苹果较早用于限制XNU修改受保护页表的机制。

对于依赖PPL的设备，仅获得Kernel Read/Write可能不足以完成某些内核代码修改，因此攻击链还可能需要PPL绕过阶段。

Coruna的价值之一，就在于整合了这类针对不同版本的安全机制绕过能力。

## 三、DarkSword：iOS 18时代的JavaScript漏洞链

DarkSword与Coruna最大的区别，是它采用了不同的后期攻击实现策略。

Google研究指出，DarkSword使用纯JavaScript完成各阶段攻击及最终载荷，这使其不必通过传统方式绕过PPL或SPTM来执行未签名原生二进制代码。

这不等于SPTM被突破，而是攻击者采用了不同的执行路径。

### DarkSword涉及的六个CVE

| CVE编号 | 组件 | 安全问题 |
|--------|------|---------|
| CVE-2025-31277 | JavaScriptCore | JIT优化相关内存破坏 |
| CVE-2025-43529 | JavaScriptCore | JIT垃圾回收相关内存破坏 |
| CVE-2026-20700 | dyld | 用户态PAC绕过 |
| CVE-2025-14174 | ANGLE | 内存破坏及沙盒逃逸 |
| CVE-2025-43510 | XNU | 内存管理漏洞 |
| CVE-2025-43520 | XNU | 内核内存破坏与权限提升 |

并非每次攻击都同时使用六个CVE；JavaScriptCore漏洞的选择与目标iOS版本有关。

DarkSword的攻击逻辑可以概括为：

```
1. Safari / WebContent
       ↓
2. JavaScriptCore RCE
       ↓
3. dyld PAC Bypass
       ↓
4. ANGLE / GPU Sandbox Escape
       ↓
5. XNU Kernel Exploitation
       ↓
6. JavaScript Payload
```

其攻击链能够取得内核级权限，但这并不自动证明攻击者获得了SPTM、TXM或Exclaves的控制权。

## 四、最关键的问题：DarkSword是否绕过了SPTM/TXM？

需要区分三种情况：

**1. Kernel Exploit成功**

攻击者在XNU内核中获得较高权限或内存访问能力。

**2. SPTM Bypass成功**

攻击者突破SPTM所强制执行的内存映射或物理页类型保护规则。

**3. Exclave Compromise成功**

攻击者突破独立隔离环境，获取Exclave内部的代码执行能力或受保护数据。

这三种情况不能画等号。

目前Google公开的DarkSword研究支持其完成内核权限提升，并指出其JavaScript实现规避了执行未签名原生代码所需的部分传统保护绕过需求；不能据此断言DarkSword已经攻破SPTM、TXM或Secure Kernel。

这也是研究苹果新一代安全架构时最值得关注的技术分界线。

## 五、两套攻击工具对iOS安全架构的启示

Coruna表明，攻击者可以针对不同iOS版本整合大量漏洞，逐层突破浏览器、沙盒、内核和页表保护。

DarkSword则说明，即使新的硬件安全机制限制了传统攻击方式，攻击者仍可能通过JavaScript运行时、合法进程上下文以及系统接口组合，寻找新的攻击路径。

对普通用户而言，最重要的防护措施是升级至设备支持的最新安全版本。对于面临定向攻击风险的用户，可以考虑启用锁定模式（Lockdown Mode）。研究人员已确认相关漏洞在后续iOS更新中获得修复。
