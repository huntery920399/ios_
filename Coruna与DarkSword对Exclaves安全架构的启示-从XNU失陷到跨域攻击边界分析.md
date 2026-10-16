# Coruna与DarkSword对Exclaves安全架构的启示：从XNU失陷到跨域攻击边界分析

Coruna/DarkSword真正值得研究的，不是"有没有打穿Exclaves"，而是它们在XNU已经失陷的情况下，还能把攻击者推进到哪里，以及哪些新的安全边界仍然成立。

截至目前公开资料，没有证据表明Coruna或DarkSword已经直接攻破Secure Kernel或Exclaves本身。相反，公开分析显示，它们主要证明了XNU及其上层攻击面的可利用性，而苹果新架构的意义正是在这里体现出来。

## 一、先给结论：Coruna/DarkSword ≠ Exclaves被攻破

可以把现代iOS攻击链画成：

```text
                 WebKit / JavaScriptCore
                           │
                           ▼
                    Safari / Web进程
                           │
                           ▼
                    Sandbox Escape
                           │
                           ▼
                       XNU Kernel
                           │
                  ┌────────┴────────┐
                  ▼                 ▼
             普通系统资源       SPTM/TXM保护
                                    │
                                    ▼
                             Secure Kernel
                                    │
                                    ▼
                                Exclaves
```

Coruna和DarkSword已经证明攻击者可以走到相当深的位置：

```text
WebKit
  ↓
Sandbox
  ↓
XNU
  ↓
Kernel-level compromise
```

但这条链并不自然地继续变成：

```text
Kernel
  ↓
Secure Kernel
  ↓
Exclave
```

这正是SPTM/TXM/Exclaves架构的安全意义。

苹果官方对SPTM/TXM的描述明确指出：SPTM运行在高于Kernel的权限级别，TXM负责执行代码执行策略；即便TXM遭到攻陷，也不会自动意味着SPTM保护被绕过。对于A15及更新的A系列以及M2及更新的M系列平台，SPTM/TXM组合用于替代PPL，并降低对Kernel信任的依赖。

## 二、Coruna对Secure Kernel的实际威胁

Coruna覆盖范围非常广。

Google Threat Intelligence Group披露，Coruna包含5条完整iOS攻击链、23个漏洞利用组件，覆盖iOS 13.0至17.2.1。部分链包含非公开的缓解措施绕过技术。

其典型攻击路径可以抽象成：

```text
恶意网页
   │
   ▼
WebKit RCE
   │
   ▼
PAC / Mitigation Bypass
   │
   ▼
Sandbox Escape
   │
   ▼
Kernel Exploit
   │
   ▼
Kernel Privilege
```

这里最后一步非常关键。

**Kernel Privilege并不等于Secure Kernel Privilege**

XNU Kernel属于：

普通高权限世界

而Secure Kernel / Exclaves属于：

独立保护域

所以：

```text
XNU被攻破
      ≠
SPTM被攻破
      ≠
Secure Kernel被攻破
      ≠
Exclave被攻破
```

这实际上是苹果新架构最核心的安全收益。

## 三、DarkSword更加能说明这个问题

DarkSword针对的是更晚的iOS版本。

Google披露其针对iOS 18.4–18.7，并使用6个漏洞完成完整攻击链，最终能够获得full kernel privileges。

其中一个关键阶段利用：

**CVE-2025-43510**

这是XNU内存管理中的copy-on-write漏洞，DarkSword利用它在mediaplaybackd环境中建立进一步的利用能力。

随后：

**CVE-2025-43520**

针对XNU VFS中的竞争条件，帮助建立物理和虚拟内存读写能力。

这些都是非常典型的：

Kernel Exploitation

而不是：

Secure Kernel Exploitation

## 四、最值得注意的地方：DarkSword并没有简单"绕过SPTM"

这一点非常容易被误解。

Google明确指出，DarkSword采用**纯JavaScript**完成整个攻击链以及最终payload，因此不需要寻找传统意义上用于绕过PPL/SPTM、从而执行未签名原生代码的漏洞。

也就是说：

```text
传统攻击思路：

Kernel R/W
    ↓
修改受保护代码
    ↓
执行自己的Native Payload

可能受到：
PPL
SPTM
TXM

的限制。
```

DarkSword采取的是另一条路线：

```text
JavaScript
   ↓
已有执行环境
   ↓
Native API / IPC
   ↓
Kernel primitives
   ↓
JavaScript-based payload
```

这是一种非常重要的安全研究启示：

**攻击者不一定需要"打穿一道墙"，也可以寻找墙两侧已经存在的合法接口。**

因此，SPTM安全性提高了，并不意味着Kernel exploit失去价值。

## 五、为什么Exclaves是下一道真正的边界？

假设攻击者已经拥有：

Kernel R/W

传统iOS模型中，这种能力非常危险。

但新的架构增加了：

```text
              XNU
               │
          Kernel R/W
               │
               X
               │
       ┌───────┴───────┐
       │               │
       ▼               ▼
普通内核资源       SPTM保护域
                       │
                       ▼
                    TXM
                       │
                       ▼
                Secure Kernel
                       │
                       ▼
                   Exclaves
```

研究论文对SPTM的分析指出，它通过physical frame retyping以及memory mapping rules建立不同的信任域，并将TXM等功能从传统XNU信任边界中隔离出来；论文进一步认为，这为Exclaves提供了基础，使部分敏感组件能够脱离XNU直接控制。

因此，攻击者真正面对的是：

从"Kernel Exploit"升级成"Cross-Domain Exploit"。

## 六、Exclaves真正的攻击面在哪里？

这也是未来iOS安全研究最重要的方向。

Exclave并不是一个"神秘黑盒"。

它仍然需要与XNU交换：

- 请求；
- 数据；
- buffer；
- handle；
- 状态；
- 资源。

所以：

```text
XNU
 │
 │ IPC
 ▼
Secure Kernel
 │
 │ IPC
 ▼
Exclave Service
```

这里必然存在攻击面。

2025年的研究已经确认，Exclaves通信体系包含多种通信机制，其中包括：

- xnuproxy
- Tightbeam IPC
- IPC + shared memory

并且重点研究了资源生命周期、消息验证以及跨域数据流。

2026年的安全研究进一步将Secure Kernel、Tightbeam、XRT scheduler messages、Exclave resources和Conclaves列为主要分析对象。

## 七、因此，DarkSword之后真正值得关注的是"代理攻击"

可以把下一代攻击模型抽象成：

```text
Attacker
   │
   ▼
Compromised XNU
   │
   ▼
xnuproxy / IPC
   │
   ▼
Tightbeam endpoint
   │
   ▼
Exclave service
```

攻击者不一定需要直接执行：

Exclave Code

如果可以利用一个合法的Exclave服务接口：

```text
合法请求
     ↓
参数边界错误
     ↓
Exclave Service Bug
     ↓
Secure-domain primitive
```

攻击面就发生了变化。

这也是为什么Tightbeam接口本身会成为非常重要的安全边界。

## 八、Shared Memory可能比普通IPC更值得关注

跨域通信通常不能只靠小型消息。

例如：

- Camera Frame
- Audio Buffer
- AI Tensor
- Large Data

不可能每次都完整复制。

因此会出现：

```text
XNU Memory
     │
     │ Shared / Mapped Buffer
     ▼
Secure Domain
```

安全问题于是从：

"消息是否安全？"

进一步变成：

"这个buffer究竟属于谁？"

以及：

- 谁可以写？
- 谁可以读？
- 生命周期由谁管理？
- 什么时候可以解除映射？
- 是否可以重复使用？
- 资源释放后是否仍可访问？

2026年的研究议题已经把ownership、lifetimes、validation points列为Exclaves IPC安全分析的重要内容。

## 九、因此可以建立一张"攻击距离图"

这是理解Coruna/DarkSword与新安全架构关系最直观的方法：

```text
距离       安全边界

0          WebKit
│
1          Sandbox
│
2          XNU
│
3          PPL / SPTM / TXM
│
4          Secure Kernel
│
5          Exclave IPC
│
6          Exclave Service
│
7          更高价值安全资源
```

**Coruna：**

0 → 1 → 2

并在部分攻击链中继续突破更多传统缓解措施。

**DarkSword：**

0 → 1 → 2

并取得Kernel级权限。

但公开研究没有证明其继续完成：

2 → 3 → 4 → 5 → 6

这恰恰说明新的安全边界已经改变了攻击者的工作量。

## 十、对Secure Kernel而言，最大的威胁不是"Kernel R/W"

而是：

**Cross-Domain Trust Confusion**

即：

一个低信任域中的数据，被高信任域错误地当成可信数据。

例如概念上：

```text
XNU：

"这是合法的buffer"


Secure Kernel：

"好的"


Exclave：

"开始处理"
```

如果验证逻辑存在缺陷：

```text
Attacker-controlled data
          ↓
XNU
          ↓
IPC
          ↓
Exclave
          ↓
Security bug
```

这类漏洞可能比传统Kernel UAF更加重要。

因为它直接攻击的是：

**信任边界本身。**

## 十一、Coruna/DarkSword给Exclaves安全架构的启示

可以归纳成四点。

**第一：SPTM有效，但不是"漏洞终结者"**

SPTM降低Kernel compromise的后果，但无法消灭：

- XNU漏洞；
- WebKit漏洞；
- IPC漏洞；
- 服务逻辑漏洞。

苹果官方也将SPTM描述为针对页表和代码完整性的重要隔离机制，而不是整个系统的万能防护。

**第二：Kernel exploit仍然具有价值**

DarkSword已经证明：

Kernel R/W

仍然可以形成完整攻击链的一部分。

**第三：Exclaves把研究重点推向IPC**

未来真正值得审计的是：

```text
XNU
 ↓
xnuproxy
 ↓
Tightbeam
 ↓
Secure Kernel
 ↓
Exclave
```

而不是单纯研究XNU。

**第四：Secure Kernel失陷的价值远高于普通Kernel漏洞**

如果普通XNU漏洞：

Compromise XNU

那么Exclave漏洞可能意味着：

Compromise Trusted Domain

两者在安全模型中的位置完全不同。

## 十二、最终安全模型

因此，Coruna/DarkSword之后的现代iOS安全模型可以总结成：

```text
             WebKit
                │
                ▼
             Sandbox
                │
                ▼
               XNU
                │
          Kernel Exploit
                │
                ▼
       ┌────────────────┐
       │ SPTM / TXM     │
       │                │
       │ Memory/Code    │
       │ Isolation      │
       └───────┬────────┘
               │
               ▼
         Secure Kernel
               │
        Tightbeam / IPC
               │
               ▼
           Exclaves
               │
               ▼
       Sensitive Services
```

Coruna和DarkSword的真正意义，是证明"传统XNU边界"仍然可以被攻击；而SPTM、TXM、Secure Kernel和Exclaves的意义，则是让"XNU被攻破"不再自动等于"整个设备的最高安全边界被攻破"。

目前公开研究更支持把Exclaves看成Coruna/DarkSword之后的下一层防御边界，而不是已经被这两套攻击链直接击穿的组件。

**安全研究角度的核心结论：**

Coruna/DarkSword主要把问题推进到了"如何攻破XNU"；SPTM/TXM/Exclaves则把下一阶段问题变成了"如何在XNU已经失陷的情况下跨越可信域边界"。这也是未来苹果平台漏洞研究从传统Kernel Exploitation向Cross-Domain / Secure Kernel / IPC Security转移的重要原因。
