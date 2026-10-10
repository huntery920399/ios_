# iPhone 短信链接触发漏洞网络安全分析报告

| 项目 | 内容 |
| --- | --- |
| 报告名称 | iPhone 短信链接触发漏洞网络安全分析报告 |
| 报告版本 | V1.0 |
| 编制日期 | 2026-10-09 |
| 情报截止日期 | 2026-10-09 |
| 威胁等级 | **严重（Critical）** |
| 适用对象 | 网络安全人员、企业 IT/安全团队、移动终端管理员、高价值目标用户 |

咨询ios系统请咨询 telegram：https://t.me/one00190

> **合规声明**：本报告仅用于防御性安全研究、风险评估和事件响应，不提供漏洞利用代码或未授权攻击指导。文中 IOC 应在获得授权的网络与终端环境内使用。

---

## 1. 执行摘要

iPhone 的短信通道（SMS/MMS 与 iMessage）长期以来是高级持续性威胁（APT）和商业间谍软件投递零点击漏洞利用的首要攻击面。与需要用户点击网页链接的水坑攻击不同，短信链接触发类攻击可在受害者**完全不交互**或**仅需一次预览**的情况下完成从初始投递到载荷执行的全链条攻击。

2021—2026 年间，多家威胁情报机构和安全研究团队公开披露了多条通过短信/iMessage 链接触发的高级攻击链：

- **FORCEDENTRY**（CVE-2021-30860）：NSO Group 通过 iMessage 发送恶意 GIF 图片，在无需用户交互的情况下实现代码执行，用于监控记者和人权活动人士；
- **BLASTPASS**（CVE-2023-41990）：通过 iMessage 发送恶意 PassKit 文件，结合后续漏洞实现完整设备控制；
- **Operation Triangulation**（2023）：通过 iMessage 附件触发 Apple 未文档化的 TrueType 字体指令，实现任意内存读写；
- **Predator 间谍软件**（2023—2024）：通过短信中的钓鱼链接引导受害者访问恶意网页，触发 WebKit 零日漏洞链；
- **Coruna 工具包**（2025—2026）：虽然主要通过网页投递，但其短信/社交工程引导链路同样将受害者导向恶意 WebKit 利用页面。

这些攻击表明，短信通道是 iOS 生态中风险最高的入口之一，其威胁等级不亚于浏览器水坑攻击。

### 1.1 核心风险结论

| 风险项 | 结论 |
| --- | --- |
| 攻击门槛 | 零点击攻击无需任何用户交互；链接点击型攻击仅需一次点击或预览 |
| 影响范围 | 所有 iPhone 设备，覆盖 iOS 14.x 至 iOS 17.x（已修补版本除外） |
| 技术影响 | 远程代码执行、沙箱逃逸、内核提权、PAC 绕过、完整设备控制 |
| 主要目标 | 记者、律师、外交官、人权工作者、政府官员、企业高管 |
| 持久化 | 部分攻击链可实现重启后持久化（plist 注入、MDM 配置） |
| 综合等级 | **严重**：零点击攻击可在受害者完全不知情的情况下完成设备失陷 |

---

## 2. 攻击面分析

### 2.1 iOS 短信架构

iPhone 的短信系统包含两个独立的通信协议栈：

| 协议 | 技术特征 | 攻击面 |
| --- | --- | --- |
| SMS/MMS | 传统电信协议，通过蜂窝网络传输，由 `CommCenter` 和 `CoreTelephony` 处理 | 协议解析漏洞、基带漏洞、MMS 媒体解析 |
| iMessage | Apple 私有端到端加密协议，通过互联网传输，由 `IMDaemonCore` 处理 | 附件解析、链接预览、Universal Links、PassKit、消息扩展 |

两个协议栈均在 `com.apple.MobileSMS` 进程中运行，该进程具有特殊的沙箱权限，可直接访问通讯录、通知中心和部分系统 IPC 接口。

### 2.2 链接触发的三种攻击模式

#### 模式一：零点击附件利用（Zero-Click Attachment）

```text
攻击者发送 iMessage（含恶意附件）
                    │
                    ▼
         iMessage 自动解析附件
         （无需用户打开或点击）
                    │
                    ▼
         附件解析器漏洞触发
         （TrueType 字体、PDF、GIF、PassKit）
                    │
                    ▼
         WebContent / 沙箱内 RCE
                    │
                    ▼
         沙箱逃逸 → 内核提权 → 完整控制
```

此模式完全不需要受害者进行任何操作。iMessage 在收到消息时会自动对附件进行预处理（生成缩略图、解析元数据、渲染链接预览），这一过程即可触发漏洞。

#### 模式二：链接预览触发（Link Preview Rendering）

```text
攻击者发送包含 URL 的 iMessage/SMS
                    │
                    ▼
         Messages 自动提取 URL
         并请求链接预览
                    │
                    ▼
         后台加载目标网页
         （WebKit 渲染引擎）
                    │
                    ▼
         恶意网页检测 iOS 设备指纹
                    │
                    ▼
         触发 WebKit RCE 漏洞链
                    │
                    ▼
         沙箱逃逸 → 内核提权 → 完整控制
```

iMessage 的链接预览功能会在后台自动加载 URL 对应的网页以生成预览卡片。此过程使用 WebKit 引擎，且受害者无需点击链接或查看预览。

#### 模式三：社会工程引导点击（Social Engineering Click-Through）

```text
攻击者发送伪装为银行/快递/官方的短信
         包含恶意链接
                    │
                    ▼
         受害者点击链接
                    │
                    ▼
         Safari / 内置浏览器打开恶意网页
                    │
                    ▼
         网页触发 WebKit RCE → 完整攻击链
                    │
                    ▼
         载荷下载 → 数据窃取 → C2 回传
```

此模式需要受害者主动点击，但通过精心伪装的短信内容（如"您的包裹需要确认地址""您的银行账户异常"），点击率可显著提高。Coruna 工具包和 Predator 间谍软件均采用此模式。

### 2.3 攻击面优先级评估

| 攻击向量 | 用户交互 | 技术复杂度 | 历史在野利用 | 风险等级 |
| --- | --- | --- | --- | --- |
| iMessage 零点击附件 | 无 | 极高 | FORCEDENTRY、BLASTPASS、Triangulation | **严重** |
| iMessage 链接预览 | 无（自动触发） | 高 | 有研究原型，尚无公开在野利用 | **高** |
| Universal Links 滥用 | 一次点击 | 中 | Predator 链 | **高** |
| SMS 钓鱼链接 | 一次点击 | 中—低 | Coruna、Predator、广泛钓鱼 | **高** |
| MMS 媒体解析 | 无（自动渲染） | 高 | 历史漏洞（CVE-2019-8637 等） | **中—高** |

---

## 3. 历史在野攻击案例

### 3.1 FORCEDENTRY（CVE-2021-30860）

| 项目 | 详情 |
| --- | --- |
| 披露时间 | 2021-09（Citizen Lab + Apple） |
| 攻击者 | NSO Group（Pegasus 间谍软件） |
| 投递方式 | iMessage 发送恶意 TIFF/GIF 图片 |
| 用户交互 | **无**（零点击） |
| 漏洞原理 | CoreGraphics 的图像解码器在处理 specially crafted GIF 文件时，触发整数溢出导致堆缓冲区溢出 |
| 攻击链 | 恶意 GIF → CoreGraphics 堆溢出 → 任意内存写入 → 代码执行 → Pegasus 载荷安装 |
| 影响版本 | iOS 12.5.x — 14.7.x |
| 修复版本 | iOS 14.8（2021-09-13） |
| 受害者 | 巴林人权活动人士、印度记者、西班牙外交官等 |

**技术价值**：FORCEDENTRY 是首个被公开确认的 iOS 零点击 iMessage 攻击。它证明了即使 Apple 在 iOS 14 中引入了 Blastdoor（iMessage 安全沙箱），攻击者仍能通过精心构造的媒体文件绕过防护。

### 3.2 BLASTPASS（CVE-2023-41990）

| 项目 | 详情 |
| --- | --- |
| 披露时间 | 2023-09（Apple 紧急修复） |
| 攻击者 | NSO Group（Pegasus） |
| 投递方式 | iMessage 发送恶意 Apple PassKit（.pkpass）文件 |
| 用户交互 | **无**（零点击） |
| 漏洞原理 | PassKit 框架在解析恶意 .pkpass 文件时触发内存损坏 |
| 攻击链 | 恶意 PassKit → 内存损坏 → RCE → 结合 CVE-2023-41991（沙箱逃逸）+ CVE-2023-41992（内核提权） → 完整设备控制 |
| 影响版本 | iOS 12.x — 16.6.1 |
| 修复版本 | iOS 16.6.1（2023-09-21，同日修复三个零日） |

**技术价值**：Apple 在同一天紧急修复三个零日漏洞，这是 iOS 安全史上最快的批量修复之一。BLASTPASS 表明攻击者已经能够利用 PassKit 这一相对冷门的框架实现零点击攻击。

### 3.3 Operation Triangulation（2023）

| 项目 | 详情 |
| --- | --- |
| 披露时间 | 2023-06（Kaspersky） |
| 攻击者 | 未知国家级 APT（归因争议） |
| 投递方式 | iMessage 发送含恶意字体文件的附件 |
| 用户交互 | **无**（零点击） |
| 漏洞原理 | 利用 Apple 未文档化的 ADJUST TrueType 字体指令实现任意内存读写 |
| 攻击链 | 恶意字体 → ADJUST 指令原语 → 任意内存读写 → XPC 沙箱逃逸 → CVE-2023-32434（内核提权）→ CVE-2023-38606（MMIO 寄存器直写绕过硬件缓解）→ 内核植入 |
| 影响版本 | iOS 12.x — 16.5.x |
| 修复版本 | iOS 16.5.1（2023-06） |

**技术价值**：首次公开披露利用 Apple 未文档化字体指令的攻击；利用了 A15/A16 芯片上一个未被公开记录的硬件 MMIO 寄存器，暗示攻击者拥有 Apple 硬件的深度知识。

### 3.4 Predator 间谍软件短信投递链（2023—2024）

| 项目 | 详情 |
| --- | --- |
| 披露时间 | 2023-11（Citizen Lab） |
| 攻击者 | Intellexa（Predator 间谍软件） |
| 投递方式 | SMS 短信包含伪装为新闻/通知的钓鱼链接 |
| 用户交互 | **需要一次点击** |
| 漏洞原理 | 恶意网页触发 WebKit 类型混淆（CVE-2023-42916/42917）→ RCE → 沙箱逃逸（CVE-2023-41991）→ 内核提权（CVE-2023-41992） |
| 攻击链 | SMS 钓鱼链接 → Safari 打开恶意页 → WebKit RCE → 三漏洞链 → Predator 载荷 |
| 影响版本 | iOS 15.x — 16.6.1 |
| 修复版本 | iOS 16.6.1（2023-09-21） |

**技术价值**：Predator 是首个被确认使用"三漏洞链"（同一天修复的三个零日）的商业间谍软件。虽然需要用户点击，但其短信伪装技术极为逼真，目标为埃及记者 Ahmed Eltantawy。

### 3.5 攻击能力演化时间线

```text
2019     CVE-2019-8637 — MMS 解析堆溢出（零点击原型）
  │
2021     FORCEDENTRY — iMessage GIF 零点击（Pegasus）
  │
2023-06  Operation Triangulation — iMessage 字体零点击
  │
2023-09  BLASTPASS — iMessage PassKit 零点击（Pegasus）
         Predator — SMS 钓鱼链接三漏洞链
  │
2024     Predator 变体 — 持续 SMS 投递 + WebKit 零日
  │
2025     GHOSTBLADE — iMessage + WebKit 水坑 + ISP 注入多通道
         Coruna — 虚假站点 WebKit 攻击链（短信引导）
  │
2026     商业间谍软件持续演化，零点击与点击型并存
```

---

## 4. 技术深度分析

### 4.1 iMessage 零点击攻击的技术原理

#### 4.1.1 Blastdoor 安全架构

iOS 14 引入的 Blastdoor 是 iMessage 的安全沙箱组件，用于隔离消息内容的解析过程：

| 组件 | 功能 | 安全边界 |
| --- | --- | --- |
| `IMDaemonCore` | iMessage 主守护进程 | 接收消息、路由到 Blastdoor |
| Blastdoor 沙箱 | 隔离解析不可信内容 | 限制文件系统和网络访问 |
| `MIMEType` 检测 | 识别附件类型 | 决定使用哪个解析器 |
| 链接预览服务 | 后台加载 URL 生成预览 | 使用 WebKit 引擎 |
| PassKit 渲染 | 渲染 .pkpass 文件 | 独立解析器 |
| 缩略图生成 | 为图片/视频生成预览 | CoreGraphics / ImageIO |

尽管 Blastdoor 显著提高了攻击门槛，但 FORCEDENTRY、BLASTPASS 和 Triangulation 均成功绕过了其防护。核心原因是 Blastdoor 仍然需要调用系统解析器来处理各类附件格式，而这些解析器本身就是攻击面。

#### 4.1.2 CoreGraphics 图像解析漏洞（FORCEDENTRY 类）

```text
恶意 GIF/TIFF 文件结构：
┌─────────────────────────────────┐
│ 文件头（合法格式标识）           │
├─────────────────────────────────┤
│ 图像数据（精心构造的畸形数据）   │
│ → 触发整数溢出                  │
│ → 导致堆缓冲区分配过小           │
│ → 后续写入操作越界               │
│ → 覆盖相邻堆对象的元数据         │
│ → 劫持控制流                    │
└─────────────────────────────────┘
```

关键利用技术：

- **整数溢出**：图像尺寸或颜色表大小的算术运算溢出，导致分配过小的缓冲区；
- **堆风水**：通过精确控制堆分配序列，使恶意数据覆盖特定的目标对象；
- **类型混淆**：利用 CoreGraphics 内部对象的虚函数表或结构体布局实现控制流劫持。

#### 4.1.3 TrueType 字体指令漏洞（Triangulation 类）

Apple 的 TrueType 字体解析器支持一组未文档化的私有指令（ADJUST 指令），这些指令可以：

- 直接操作字体渲染引擎的内部内存区域；
- 通过精心构造的字体 hinting 程序实现任意内存读写原语；
- 绕过 Blastdoor 沙箱的文件系统限制（字体数据内嵌在 iMessage 附件中）。

#### 4.1.4 PassKit 解析漏洞（BLASTPASS 类）

.pkpass 文件本质上是一个 ZIP 压缩包，包含 JSON 清单文件和图片资源。iMessage 在收到 .pkpass 附件时会自动解析并渲染预览卡片。解析过程中的漏洞可能出现在：

- ZIP 解压时的路径遍历或缓冲区溢出；
- JSON 清单文件的字段解析（整数溢出、类型混淆）；
- 图片资源的 ImageIO 解码（与 FORCEDENTRY 类似的堆溢出）。

### 4.2 链接预览攻击的技术原理

iMessage 的链接预览功能在后台自动执行以下操作：

1. 检测到消息中的 URL；
2. 通过 `NSExtension` 机制调用链接预览服务；
3. 使用 WebKit 引擎加载目标网页；
4. 截取网页快照生成预览卡片；
5. 缓存预览结果。

**攻击窗口**：步骤 3 中，WebKit 引擎在后台加载攻击者控制的网页。如果该网页包含针对特定 iOS 版本的 WebKit 漏洞利用代码，且设备指纹识别确认目标为 iPhone，则可在受害者不知情的情况下触发 RCE。

**与浏览器攻击的差异**：

| 维度 | 浏览器水坑攻击 | iMessage 链接预览攻击 |
| --- | --- | --- |
| 用户交互 | 需要访问网页 | 无需交互（自动触发） |
| 浏览器引擎 | Safari/WebKit | WebKit（相同引擎） |
| 沙箱环境 | WebContent 沙箱 | WebContent 沙箱（类似） |
| 攻击可见性 | 用户可看到浏览器界面 | 完全后台，用户无感知 |
| 攻击窗口 | 用户主动浏览时 | 收到消息即触发 |

### 4.3 SMS 钓鱼链接攻击的技术原理

#### 4.3.1 短信伪装技术

攻击者使用以下技术提高短信的可信度和点击率：

| 技术 | 说明 | 示例 |
| --- | --- | --- |
| 号码伪装（SMS Spoofing） | 伪造发送者号码为官方号码 | 伪装为银行客服号码、Apple 官方号码 |
| 闪信（Flash SMS） | 直接显示在屏幕上，不存入收件箱 | 伪装为系统警告 |
| 品牌模板 | 使用与官方短信一致的格式和措辞 | "【XX银行】您的账户存在异常..." |
| 短链服务 | 使用 URL 缩短服务隐藏真实目标 | bit.ly、t.co 等 |
| 同形字域名 | 使用视觉上相似的国际域名 | `app1e.com`（用数字 1 替代字母 l） |

#### 4.3.2 恶意网页利用链

受害者点击短信中的链接后，恶意网页执行以下流程：

```text
1. 设备指纹识别
   → 检测 User-Agent、WebGL 渲染器、屏幕分辨率、CPU 核心数
   → 确认为 iPhone 并识别 iOS 版本和芯片型号
   │
2. 环境检测
   → 检测是否为分析/沙箱环境
   → 检测锁定模式（JIT 是否可用）
   → 检测无痕浏览模式
   │
3. 漏洞选择
   → 根据 iOS 版本选择匹配的 WebKit RCE 模块
   → 根据芯片型号选择 PAC 绕过模块
   │
4. 漏洞利用
   → WebKit RCE → PAC 绕过 → 沙箱逃逸 → 内核提权 → PPL 绕过
   │
5. 载荷投递
   → 下载并注入最终载荷
   → 建立 C2 通信
   → 开始数据窃取
```

### 4.4 Universal Links 滥用

Universal Links 允许应用通过 HTTPS 链接直接打开对应的原生应用。攻击者可利用此机制：

- 构造指向合法应用（如银行 App）的 Universal Link，但附加恶意参数；
- 利用应用间通信（XPC/URL Scheme）在应用链中触发漏洞；
- 通过 `sms:` URL Scheme 构造可自动发送短信的链接（需用户确认）。

---

## 5. 关键 CVE 清单

### 5.1 iMessage/短信相关零点击漏洞

| CVE | 披露时间 | 组件 | 漏洞类型 | 攻击模式 | 修复版本 |
| --- | --- | --- | --- | --- | --- |
| CVE-2021-30860 | 2021-09 | CoreGraphics (ImageIO) | 堆缓冲区溢出 | iMessage GIF 零点击 | iOS 14.8 |
| CVE-2023-41990 | 2023-09 | PassKit | 内存损坏 | iMessage PassKit 零点击 | iOS 16.6.1 |
| CVE-2023-32409 | 2023-05 | WebKit Process Model | 沙箱逃逸 | iMessage 附件触发 | iOS 16.5.1 |
| CVE-2023-38606 | 2023-06 | AppleAVD | MMIO 寄存器直写 | iMessage 字体附件 | iOS 16.5.1 |
| CVE-2023-32434 | 2023-06 | XNU (vm_map) | 整数溢出 | iMessage 附件链 | iOS 16.5.1 |
| CVE-2019-8637 | 2019-08 | CoreTelephony / MMS | 堆溢出 | MMS 零点击 | iOS 12.4.1 |

### 5.2 短信链接点击型漏洞

| CVE | 披露时间 | 组件 | 漏洞类型 | 攻击模式 | 修复版本 |
| --- | --- | --- | --- | --- | --- |
| CVE-2023-42916 | 2023-11 | WebKit (JSC) | OOB read | SMS 链接 → WebKit | iOS 17.1.2 |
| CVE-2023-42917 | 2023-11 | WebKit (JSC) | 类型混淆 | SMS 链接 → WebKit | iOS 17.1.2 |
| CVE-2023-41991 | 2023-09 | Security 框架 | 证书验证绕过 | SMS 链接 → 沙箱逃逸 | iOS 16.6.1 |
| CVE-2023-41992 | 2023-09 | XNU Kernel | 权限提升 | SMS 链接 → 内核提权 | iOS 16.6.1 |
| CVE-2024-23222 | 2024-01 | WebKit (JSC) | 类型混淆 | SMS 链接 → WebKit | iOS 17.3 |
| CVE-2024-27834 | 2024-05 | WebKit (JSC) | 整数溢出 | SMS 链接 → WebKit | iOS 17.5 |
| CVE-2025-24201 | 2025-02 | WebKit | OOB write | SMS 链接 → WebKit | iOS 18.3 |

### 5.3 基带与协议层漏洞

| CVE | 披露时间 | 组件 | 漏洞类型 | 说明 |
| --- | --- | --- | --- | --- |
| CVE-2022-26712 | 2022-05 | Baseband | 越界写入 | 蜂窝基带协议处理漏洞 |
| CVE-2021-30879 | 2021-10 | IOMobileFrameBuffer | 越界写入 | 显示驱动漏洞，可被基带触发 |
| CVE-2023-42824 | 2023-09 | XNU Kernel | 本地提权 | 可与短信链攻击组合使用 |

---

## 6. 锁定模式（Lockdown Mode）对短信攻击的防护

### 6.1 保护机制

iOS 16+ 的锁定模式对短信通道实施以下限制：

| 保护项 | 具体限制 | 防御效果 |
| --- | --- | --- |
| iMessage 附件 | 禁止大部分附件类型，仅允许图片 | 阻断 FORCEDENTRY、BLASTPASS、Triangulation 类零点击攻击 |
| 链接预览 | 禁用链接预览自动加载 | 阻断链接预览后台 WebKit 攻击 |
| Universal Links | 限制 Universal Links 自动打开应用 | 减少应用间攻击面 |
| 配置描述文件 | 阻止安装 MDM 配置描述文件 | 阻断恶意 MDM 安装 |
| FaceTime | 阻止未曾通话的号码来电 | 减少通信攻击面 |

### 6.2 有效性评估

| 攻击模式 | 锁定模式是否有效 | 说明 |
| --- | --- | --- |
| iMessage 零点击附件（FORCEDENTRY 类） | **有效** | 附件被阻断 |
| iMessage 链接预览 | **有效** | 预览被禁用 |
| SMS 钓鱼链接（点击型） | **部分有效** | 链接仍可点击，但 JIT 被禁用可降低 WebKit RCE 成功率约 60—70% |
| 基带协议攻击 | **部分有效** | 锁定模式不直接保护基带层 |
| MDM 恶意配置安装 | **有效** | 配置描述文件被阻断 |

### 6.3 局限性

- 锁定模式不能阻止 SMS 短信本身的接收和显示；
- 受害者仍可能点击短信中的钓鱼链接；
- 非 JIT 路径的 WebKit 漏洞（ImageIO、CoreGraphics、字体解析）在锁定模式下仍可被利用；
- 蜂窝基带攻击面不受锁定模式直接影响。

---

## 7. 检测与威胁狩猎

### 7.1 终端侧检测

| 检测手段 | 说明 | 适用场景 |
| --- | --- | --- |
| sysdiagnose 定期采集 | 高管/VIP 每周采集一次，保留 90 天 | 企业 VIP 监控 |
| Amnesty MVT 扫描 | 对 iTunes 加密备份做 IOC 匹配 | 疑似感染后取证 |
| iMazing Spyware Detection | 商业化扫描，覆盖 Pegasus/Predator/GHOSTBLADE IOC | 快速筛查 |
| shutdown.log 审计 | 检查异常进程名和 SIGTERM 模式 | 无文件攻击检测 |
| crashlog 频率分析 | `MobileSMS`、`WebContent`、`mediaserverd` 异常崩溃频率 | 攻击尝试指示 |
| Apple Threat Notifications | Apple 主动向可能遭国家级攻击的用户发送通知 | 最终告警 |

### 7.2 网络侧检测

```text
# iMessage 零点击攻击网络特征检测示例
alert tls any any -> any any (
    msg:"[iOS-SMS] Suspicious iMessage relay via short-lived cert";
    flow:to_server,established;
    tls.sni; content:".cdn-"; pcre:"/\.cdn-[a-z]{4,6}\.(com|net|io)$/";
    ja4.hash; content:"t13d1517h2_8daaf6152771_e5627efa2ab1";
    classtype:trojan-activity;
    sid:9000200; rev:1;
)
```

```text
# SMS 钓鱼链接 WebKit 载荷检测
alert http any any -> any any (
    msg:"[iOS-SMS] Obfuscated JS targeting iPhone via SMS link";
    flow:to_client,established;
    http.user_agent; content:"iPhone"; nocase;
    http.response_body; content:"SharedArrayBuffer"; distance:0;
    http.response_body; content:"Atomics"; distance:0;
    dsize:>50000;
    classtype:trojan-activity;
    sid:9000201; rev:1;
)
```

### 7.3 短信网关侧检测

企业短信网关和 MDM 应监测：

- 来自已知恶意号码或新注册号码的短信；
- 包含短链服务 URL 的短信（bit.ly、t.co 等）；
- 包含同形字域名的短信（`app1e.com`、`paypa1.com`）；
- 伪装为官方机构的短信模板（与已知钓鱼模板库比对）；
- 高频发送相似内容短信的号码（批量钓鱼特征）。

### 7.4 代表性 IOC

| 类型 | 标识 | 说明 |
| --- | --- | --- |
| 域名模式 | `*.cdn-[a-z]{4,6}.com` | GHOSTBLADE C2 域名模式 |
| 域名模式 | `*.static-assets-[0-9]{2}.net` | 商业间谍软件 C2 模式 |
| TLS 证书 | Let's Encrypt / ZeroSSL，有效期 90 天，Subject 无组织信息 | 间谍软件 C2 特征 |
| 短信号码模式 | 新注册虚拟号码、VoIP 号码 | 批量钓鱼特征 |
| URL 模式 | 短链服务 + 重定向到 `.xyz`/`.top` 域名 | Coruna/Predator 投递特征 |
| 进程异常 | `MobileSMS`、`WebContent`、`mediaserverd` 密集崩溃 | 攻击尝试指示 |
| 文件路径 | `/var/mobile/Library/SMS/Attachments/` 异常文件 | iMessage 附件分析 |

---

## 8. 防护建议

### 8.1 面向高风险个人

| 优先级 | 措施 | 说明 |
| --- | --- | --- |
| P0 | **启用锁定模式** | 设置 → 隐私与安全性 → 锁定模式。可阻断绝大多数零点击 iMessage 攻击 |
| P0 | **保持 iOS 最新** | 启用自动更新和安全响应自动安装 |
| P1 | **不点击不明短信链接** | 银行、快递、政府类短信中的链接应通过官方 App 或官网验证 |
| P1 | **使用硬件安全密钥** | YubiKey / Titan 保护 Apple ID，防止账户接管 |
| P2 | **独立设备处理敏感事务** | 高价值操作（银行转账、钱包管理）使用独立设备 |
| P2 | **定期 sysdiagnose 审计** | 交由专业团队进行移动取证分析 |
| P3 | **接到 Apple Threat Notification 后立即响应** | 保留设备证据，联系专业移动安全团队 |

### 8.2 面向企业

| 控制项 | 建议 |
| --- | --- |
| MDM 锁定模式 | 对 C-Suite、法务、安全岗位强制下发锁定模式配置 |
| iOS 版本合规 | MDM 强制最低版本；阻断 iOS < 17.3 及无法补丁设备访问企业资源 |
| 补丁 SLA | 在野利用相关更新 24 小时内完成，高风险人员应当日安装 |
| 短信网关过滤 | 企业短信网关部署钓鱼链接检测和号码信誉评估 |
| 网络阻断 | 导入已知 IOC，监测新注册 `.xyz`、短链重定向和可疑 `.min.js` 载荷 |
| 条件访问 | 将 iOS 版本、设备合规、锁定模式状态纳入零信任访问控制 |
| 事件响应 | 建立移动终端证据保全、账户吊销和专业取证流程 |
| 员工培训 | 针对短信钓鱼进行定期演练和意识培训 |

### 8.3 面向安全研究员

- 重点关注 iMessage 附件解析器（CoreGraphics、PassKit、TrueType、PDF）；
- 研究 Blastdoor 沙箱的 IPC 接口和边界条件；
- 关注 `CommCenter`（基带处理）和 `IMDaemonCore`（iMessage 守护进程）的漏洞；
- 使用 Corellium 或 Apple Security Research Device Program 进行内核调试；
- 通过 Apple Security Bounty 报告发现的漏洞（最高 200 万美元）。

---

## 9. 事件响应流程

发现疑似短信链接攻击或 Apple Threat Notification 时：

### 阶段一：立即控制

1. 将设备切换至**飞行模式**（不关机，保留内存证据）；
2. 不要使用该设备修改密码或迁移钱包；
3. 记录设备型号、iOS 版本、收到的可疑短信内容、时间戳；
4. 在安全设备上撤销 Apple ID、企业 SSO、邮箱、VPN、钱包会话。

### 阶段二：证据保全

1. **不要恢复出厂设置**；
2. 保存 MDM、DNS、防火墙、代理、VPN 日志；
3. 在合法授权下采集 sysdiagnose、iTunes 加密备份、崩溃日志；
4. 将日志与已知 IOC、YARA 特征及时间线交叉比对；
5. 使用 MVT 或 iMazing 进行自动化扫描。

### 阶段三：清除与恢复

1. 在证据保全后更新至最新 iOS；必要时执行 DFU 恢复；
2. 对无法升级的设备实施永久退役或严格隔离；
3. 从安全设备轮换全部敏感凭证；
4. 数字资产迁移至新助记词生成的钱包；
5. 持续监测旧会话、异常登录、链上转账和钓鱼再攻击。

### 阶段四：复盘

- 确定攻击入口（短信号码、链接 URL、附件类型）；
- 检查同一号码是否向其他员工发送了类似短信；
- 更新短信网关过滤策略和 MDM 合规基线；
- 对受影响员工及相邻资产进行扩大排查。

---

## 10. 风险矩阵

| 维度 | 评级 | 说明 |
| --- | --- | --- |
| 零点击可达性 | 高 | iMessage 零点击攻击已有多个在野案例 |
| 点击型可达性 | 极高 | SMS 钓鱼可大规模投递 |
| 技术复杂度 | 极高（零点击）/ 中（点击型） | 零点击需要专业漏洞开发能力 |
| 机密性影响 | 严重 | 完整设备控制 → 全部数据泄露 |
| 完整性影响 | 严重 | 可注入代码、修改系统配置 |
| 持久化能力 | 中—高 | 部分链可实现重启后持久化 |
| 规模化能力 | 中（零点击）/ 高（点击型） | 零点击成本高但精准；点击型可大规模钓鱼 |
| 检测难度 | 极高 | 零点击攻击不留用户可见痕迹 |
| 综合风险 | **严重** | 对未启用锁定模式的高价值目标近乎无法自行察觉 |

---

## 11. 趋势判断（2026—2027）

- **零点击攻击持续升级**：商业间谍软件厂商持续投入资源开发新的零点击 iMessage 攻击链，目标框架从 CoreGraphics 扩展到 PassKit、字体解析、PDF 解析等更多组件。

- **MTE 重塑攻击格局**：A17/M3+ 设备的 MTE 使堆溢出类漏洞（FORCEDENTRY 类型）利用难度成倍增加，但旧设备（A12—A16）仍是攻击焦点。

- **锁定模式覆盖率提升**：Apple 持续扩展锁定模式保护范围，预计 iOS 20 将覆盖蜂窝基带和蓝牙栈，进一步压缩零点击攻击面。

- **SMS 钓鱼工业化**：AI 辅助生成高度逼真的钓鱼短信模板，结合实时设备指纹识别和自适应漏洞选择，点击型攻击的成功率将持续提高。

- **跨通道攻击融合**：攻击链可能同时使用 iMessage 零点击（初始侦察）+ SMS 钓鱼（载荷投递）+ 网页水坑（备份通道），形成多通道冗余投递。

- **基带攻击面升温**：随着 iMessage 上层通道被锁定模式压缩，攻击者可能更多关注基带协议层漏洞（CVE-2022-26712 类型），这类漏洞不受锁定模式直接影响。

---

## 12. 结论

iPhone 短信通道是 iOS 生态中风险最高的攻击入口之一。零点击 iMessage 攻击（FORCEDENTRY、BLASTPASS、Operation Triangulation）证明了即使没有任何用户交互，攻击者仍可完成从初始投递到完整设备控制的全链条攻击。SMS 钓鱼链接虽然需要用户点击，但通过精心伪装的社会工程手段，其规模化能力和成本效益使其成为商业间谍软件的首选投递方式。

对于防御方，最有效的控制措施明确如下：

- **高风险用户必须启用锁定模式**——这是阻断零点击 iMessage 攻击的最有效手段；
- **保持 iOS 更新至最新版本**——所有已知的在野零点击漏洞均已被 Apple 修补；
- **不点击不明短信中的链接**——通过官方 App 或官网验证短信中的信息；
- **企业部署 MDM 强制锁定模式和版本合规**——将设备安全状态纳入零信任访问控制；
- **对疑似感染按"已失陷"处置**——保留证据、轮换凭证、迁移资产。

**最终风险判定：严重（Critical）。**

---

## 13. 参考资料

1. Citizen Lab, "FORCEDENTRY: Pegasus Spyware's Zero-Click iMessage Exploit", 2021.
2. Kaspersky GReAT, "Operation Triangulation" 系列技术博客, 2023—2024.
3. Citizen Lab, "Predator in the Wires: Ahmed Eltantawy targeted with Predator spyware", 2023.
4. Google TAG, "Buying Spying: Insights into Commercial Surveillance Vendors", 2024.
5. Google TAG, "Coruna: The Mysterious Journey of a Powerful iOS Exploit Kit", 2026.
6. Apple Security Research, "Memory safety and Pointer Authentication on Apple platforms", 2023.
7. Apple Security Releases (https://support.apple.com/en-us/HT201222).
8. Amnesty International, Mobile Verification Toolkit (MVT) 项目文档.
9. Project Zero, "An analysis of an in-the-wild iOS Safari WebContent exploit", 2024.
10. Microsoft Threat Intelligence, "Commercial spyware and the surveillance-for-hire industry", 2025.

---

*报告结束。本报告基于截至 2026-10-09 的公开情报编制。CVE 映射、基础设施及检测指标应定期复核。*
