# iOS 17/18安全架构白皮书——基于Secure Enclave、SPTM、TXM与Exclaves的新一代可信计算体系

- **版本**：1.0
- **类型**：技术白皮书
- **领域**：移动操作系统安全、可信执行环境、硬件安全架构

## 摘要

随着移动设备逐渐成为个人数字身份、金融支付、健康数据以及人工智能计算的重要载体，现代移动操作系统面临的安全挑战已经从传统应用隔离问题，发展为面向整个计算平台的可信边界保护问题。

过去的iOS安全模型主要依赖：

- 硬件安全启动（Secure Boot）
- Secure Enclave Processor（SEP）
- 数据保护体系（Data Protection）
- 应用沙盒（Sandbox）
- 代码签名（Code Signing）
- 内核完整性保护（KIP）
- 页面保护层（Page Protection Layer，PPL）

这些机制有效降低了攻击风险，但其核心假设仍然是：

**操作系统内核是可信计算基础的一部分。**

然而，现代攻击链的发展已经证明，内核漏洞仍然可能成为整个系统安全模型的关键突破口。

因此，在iOS 17/18以及基于Apple Silicon的新一代平台中，苹果进一步推动安全架构向：

**硬件隔离 + 最小可信计算基 + 分区式可信执行模型**

方向演进。

其中：

- Secure Page Table Monitor（SPTM）
- Trusted Execution Monitor（TXM）
- Exclaves安全隔离环境

成为苹果重新设计系统安全边界的重要组成部分。

苹果官方安全文档指出，SPTM与TXM协同保护用户进程和内核进程的页表，即使攻击者获得Kernel写权限，也能够阻止关键内存映射被非法修改。在支持的平台上，SPTM/TXM组合逐渐替代传统PPL机制，并进一步降低可信计算基规模。

## 第一章 iOS安全架构演进

### 1.1 从权限控制到可信计算

早期移动操作系统安全主要依赖：

```text
应用程序
    |
权限系统
    |
操作系统内核
    |
硬件
```

安全边界集中于Kernel。

这种模式的问题在于：

如果Kernel被攻击者控制：

- 内存可被修改；
- 权限检查可能失效；
- 代码签名可能被绕过；
- 调试接口可能被利用。

因此：

**Kernel安全成为整个系统安全性的单点。**

### 1.2 iOS传统纵深防御模型

iOS长期采用多层安全设计：

```text
                 Application

                     |

              Sandbox Isolation

                     |

              Code Signing

                     |

              Kernel Security

                     |

                 Secure Boot

                     |

                    SEP

                     |

                 Hardware
```

其中：

#### Sandbox

限制应用：

- 文件访问；
- IPC能力；
- 系统资源。

#### Code Signing

保证：

只有经过苹果信任链验证的软件才能执行。

#### Kernel Protection

包括：

- Kernel Integrity Protection
- Pointer Authentication
- Fast Permission Restrictions

#### Secure Enclave

负责：

- 密钥保护；
- 生物认证；
- 加密操作。

然而，这种结构仍然存在一个问题：

**Kernel拥有过大的权限。**

因此苹果开始重新划分可信边界。

## 第二章 新一代安全目标：降低TCB

### 2.1 Trusted Computing Base概念

可信计算基（TCB）指：

**系统中必须被信任，否则安全保证无法成立的软件和硬件集合。**

传统iOS：

```text
TCB:

BootROM
 |
SEP
 |
Kernel
 |
系统服务
```

Kernel包含：

- 内存管理；
- 驱动；
- 网络；
- 文件系统；
- 权限管理。

代码规模巨大。

攻击面自然增加。

### 2.2 苹果的新安全理念

新的目标：

- 减少可信代码数量
- 提高隔离等级
- 降低Kernel权限

演进方向：

```text
传统模型：

Kernel = Trust Anchor


新模型：

Hardware
    |
SPTM
    |
TXM
    |
Exclaves
    |
Kernel
```

Kernel不再拥有最高安全权限。

## 第三章 Secure Page Table Monitor（SPTM）

### 3.1 SPTM定位

SPTM：Secure Page Table Monitor

中文可理解为：安全页表监控器

它是苹果新一代内存隔离基础。

核心任务：

**控制系统关键页表状态，防止未经授权的内存映射变化。**

### 3.2 为什么页表如此重要？

现代CPU通过页表实现：

虚拟地址：

```text
0xffff0000
```

映射到：物理内存地址。

例如：

```text
Process A

Virtual Address

        ↓

Page Table

        ↓

Physical Memory
```

如果攻击者修改页表：

可以实现：

- 读取任意内存；
- 写入Kernel数据；
- 修改代码执行权限。

因此：

**控制页表 = 控制整个系统内存安全。**

### 3.3 SPTM工作模型

传统：

```text
Application

    ↓

Kernel

    ↓

MMU

    ↓

Memory
```

问题：

Kernel可以修改自己的页表。

SPTM：

```text
Application

    ↓

Kernel

    ↓

TXM Policy

    ↓

SPTM

    ↓

MMU

    ↓

Memory
```

Kernel请求：

```text
修改页表

↓

SPTM验证

↓

允许/拒绝
```

### 3.4 SPTM安全优势

防止Kernel完全控制系统。

传统：

```text
Kernel Exploit

      ↓

Root

      ↓

Full Control
```

SPTM：

```text
Kernel Exploit

      ↓

Kernel权限

      ↓

SPTM仍保持控制
```

攻击者需要同时突破：

- Kernel
- TXM
- SPTM

攻击复杂度显著增加。

## 第四章 Trusted Execution Monitor（TXM）

### 4.1 TXM角色

TXM：Trusted Execution Monitor

负责：

- 代码执行策略；
- 信任缓存验证；
- 权限控制；
- 安全状态管理。

苹果官方架构描述中，TXM负责实际执行代码执行策略，而SPTM提供更高权限级别的隔离保护。

### 4.2 TXM与Kernel关系变化

传统：

```text
Kernel

负责：

代码验证
权限判断
执行管理
```

问题：

Kernel被攻破后：

安全策略可能失效。

新模型：

```text
Kernel

请求执行

      ↓

TXM验证

      ↓

SPTM保护

      ↓

CPU执行
```

### 4.3 TXM保护内容

#### 代码完整性

确保：

- 二进制来源可信；
- Hash匹配；
- Trust Cache有效。

#### Entitlement验证

例如：

应用请求：

```text
com.apple.private.xxx
```

TXM验证：

- 是否允许？
- 是否签名？
- 是否可信？

#### 限制动态代码执行

攻击者常利用：

- JIT
- 动态加载
- 代码注入

TXM可以限制：

```text
未知代码

↓

禁止执行
```
