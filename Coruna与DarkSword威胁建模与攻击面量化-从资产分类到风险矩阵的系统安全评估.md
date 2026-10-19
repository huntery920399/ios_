# Coruna与DarkSword威胁建模与攻击面量化-从资产分类到风险矩阵的系统安全评估

> 分析对象：2024–2026年公开分析中出现的Coruna与DarkSword iOS攻击链/商业间谍软件生态。
> 事实边界：本文只使用公开描述与可验证的iOS安全架构，不引用未公开的受害者、样本哈希、精确CVE编号或行动归因。凡属推断，均标注“推断”或“公开资料未披露”。

## 摘要
Coruna与DarkSword代表了高级iOS攻击的两种工程路线：前者以WebKit远程入口加分阶段原生载荷为特征，后者以纯JavaScript多漏洞协同、较少依赖独立原生载荷为特征。两者常被当作“漏洞利用工具”讨论，但对企业真正有价值的分析单位不是漏洞，而是从投递到外传的完整任务能力，以及这种能力穿越了哪些信任边界。

本文给出一套可复用的系统安全评估方法：先建立资产分类与信任边界，再枚举消息、浏览器、网络、无线、USB、MDM、扩展与备份八类攻击面，随后用STRIDE与移动ATT&CK建立威胁假设，最后用“可能性×影响×可利用性×检测覆盖”四因子模型把假设转化为可比较的风险分数。模型中的评分是示例，不是对真实行动的情报评估。

分析结论有三点。第一，Coruna的风险重心在获得原生载荷之后的持久化、收集与外传，检测应前移到沙箱逃逸与内核边界；DarkSword的风险重心在WebContent内的多漏洞协同与低落盘痕迹，防御应聚焦JIT攻击面、补丁延迟和会话隔离。第二，浏览器与消息仍是最高优先级入口，无线与USB属于低频但高影响的旁路。第三，企业最常见的缺口不是缺少工具，而是缺少跨阶段的检测覆盖度量，导致“已部署EDR/MDM”被误当作“已获得可见性”。

**关键词**：iOS；Coruna；DarkSword；威胁建模；攻击面量化；STRIDE；ATT&CK Mobile；WebKit；风险矩阵

## 引言
高级移动攻击的公开叙事往往被简化为“某漏洞被利用”。这种叙事对补丁团队有用，对企业安全团队却不够：同一个WebKit漏洞，在不同资产、不同网络位置、不同管理状态下造成的后果差异极大；同一条攻击链，在不同检测覆盖下也会呈现完全不同的风险。Coruna与DarkSword的价值，恰恰在于它们提供了两种可对比的能力组合，而不是两个可供背诵的CVE清单。

本文不讨论未公开的样本细节，也不对行动归属作判断。我们把Coruna与DarkSword视为“能力标签”：Coruna偏向远程入口、分阶段载荷与较完整的原生驻留；DarkSword偏向在浏览器/JavaScript上下文内完成多漏洞协同，减少对独立原生Payload的依赖。这个工作性定义足以支撑威胁建模，但不等于对两者全部能力的完整描述。

文章的结构遵循“资产—边界—攻击面—威胁—路径—量化—收敛”的顺序。读者可以把其中的表格替换成自己组织的资产清单与遥测数据，从而得到一份可审计、可复盘的iOS风险评估，而不是一次性阅读材料。

## 一、高级移动攻击为何需要威胁建模
### 1.1 从单点漏洞到任务能力
高级移动攻击通常不是一次利用，而是一条流水线：投递、初始访问、执行、持久化、提权、收集、外传。每个阶段的失败模式、可观测性和控制手段都不同。只盯着初始访问，会低估持久化与数据收集阶段的长期风险；只盯着恶意软件哈希，会错过“无文件、纯脚本、短驻留”的攻击形态。

以Coruna为例，公开分析普遍将其描述为“WebKit远程入口+分阶段载荷”，其中PlasmaLoader承担加载与后续模块衔接的角色。以DarkSword为例，公开分析普遍强调“多漏洞协同、纯JavaScript”的特征。两者的共同点是都依赖浏览器/脚本执行环境作为起点或主要执行环境，差异在于获得代码执行之后如何维持能力、如何接触敏感数据、如何把数据带出设备。

威胁建模的作用，是把“攻击者能做什么”拆成可验证的能力项，再把这些能力项映射到资产与边界。这样，防御者就能回答三个问题：哪些资产真正暴露在攻击路径上；哪些控制点能以较低成本切断路径；哪些阶段目前没有可见性。

### 1.2 传统边界模型为何失真
传统边界模型假设“内网可信、设备可控、用户可训练”。在iOS场景中，这三个假设都不稳固。设备同时连接蜂窝网、Wi-Fi、蓝牙、NFC、UWB与USB配件，云服务（iCloud、APNs、MDM）又不断穿越设备边界。用户的点击只是众多入口之一，零点击解析链、恶意配置描述文件、被攻陷的MDM、被污染的备份都可能绕过“用户不要点链接”这类单点建议。

更关键的是，设备失陷的后果不只是“数据泄露”。设备完整性本身是资产：一旦内核或安全启动链被突破，后续所有本地控制（沙箱、TCC、代码签名、钥匙串访问控制）都可能被绕过或降级。网络位置也是资产：受控设备可以作为进入企业内网的跳板，或作为中间人观察同一网络中的其他设备。把这些后果统一折算成“记录数×单价”，会严重低估高级攻击的战略价值。

因此，移动威胁建模需要同时覆盖数据、凭证、密钥、企业数据、设备完整性与网络位置六类资产，并把“边界穿越”作为核心分析对象，而不是把设备当作一个黑盒。

### 1.3 建模的输出物
一次有效的建模至少应产出六类结果：资产登记表、信任边界图、攻击面清单、威胁场景库、风险评分表、检测覆盖缺口表。它们不是文档摆设，而应能驱动三类决策：补丁与版本策略、配置与权限基线、检测工程优先级。

模型还应保留“证据强度”和“置信度”。公开分析对Coruna/DarkSword的描述并不完整，很多环节只能推断。把推断写成事实，会让风险评分产生虚假精确感；把推断明确标注，反而能让决策者知道哪些结论需要更多遥测来验证。

```text
                 ┌──────────────────────────────┐
                 │  1. 资产与业务影响            │
                 │  数据/凭证/密钥/完整性/位置   │
                 └──────────────┬───────────────┘
                                │
                                ▼
                 ┌──────────────────────────────┐
                 │  2. 信任边界与穿越机制        │
                 │  SEP/内核/沙箱/TCC/网络/USB   │
                 └──────────────┬───────────────┘
                                │
                                ▼
                 ┌──────────────────────────────┐
                 │  3. 攻击面清单与暴露度        │
                 │  消息/浏览器/无线/管理面      │
                 └──────────────┬───────────────┘
                                │
                                ▼
                 ┌──────────────────────────────┐
                 │  4. 威胁假设（STRIDE/ATT&CK） │
                 └──────────────┬───────────────┘
                                │
                                ▼
                 ┌──────────────────────────────┐
                 │  5. 四因子评分与优先级        │
                 │  L × I × X × (6-D)           │
                 └──────────────┬───────────────┘
                                │
                                ▼
                 ┌──────────────────────────────┐
                 │  6. 控制收敛与检测覆盖度量    │
                 │  补丁/配置/隔离/遥测/演练     │
                 └──────────────────────────────┘
```

## 二、Coruna与DarkSword能力画像
### 2.1 事实边界与工作性定义
本文采用以下工作性定义，目的是建立可比较的能力维度，而不是给出最终的恶意软件分类：

- Coruna：以WebKit远程入口为起点，借助分阶段载荷（公开分析中常提到PlasmaLoader）把浏览器代码执行扩展为更持久的设备访问，并具备较完整的收集与外传能力。
- DarkSword：以多个WebKit/JavaScriptCore漏洞的协同利用为核心，主要逻辑在JavaScript上下文中完成，较少依赖独立的原生Mach-O载荷。

这两个定义都带有“公开分析通常描述”的前缀。具体样本可能具备额外模块，也可能省略某些阶段；未公开的部分不应被补全为事实。

### 2.2 Coruna：远程入口与分阶段载荷
从系统安全角度看，Coruna的关键不是“用了哪个WebKit漏洞”，而是“如何把一次浏览器渲染进程的代码执行，转化为可持续的设备能力”。典型路径是：诱导目标访问恶意页面，在WebContent进程内获得初始代码执行，逃逸WebContent沙箱，获取内核读写或等价能力，然后加载分阶段载荷。PlasmaLoader这一名称在公开分析中用于描述加载器/阶段载荷，其具体模块划分、加密方式和持久化位置可能随版本变化，公开资料未披露完整细节。

分阶段设计带来两个优势。第一，初始入口可以保持较小、较隐蔽，后续模块按需下载，降低单次投递的体积和暴露面。第二，原生载荷可以直接使用POSIX、Mach、Keychain、文件系统与网络API，收集面更广，持久化选择更多。代价是落盘、进程、launchd任务、网络心跳等痕迹更多，给主机侧检测留下机会。

需要特别区分“内核读写”与“全设备控制”。即使获得内核读写，攻击者仍要面对SEP、安全隔区、Data Protection类密钥、Apple Pay安全元件等硬件边界；内核能力可以绕过沙箱与TCC，但不自动等于可以解密所有受保护数据或伪造支付凭证。威胁建模应把“内核能力”与“SEP/SE能力”分开评估，否则会高估单次内核失陷的后果。

### 2.3 DarkSword：纯JavaScript多漏洞协同
DarkSword的“纯JavaScript”应理解为“主要攻击逻辑与载荷逻辑以JavaScript表达”，而不是“全程没有原生代码执行”。多漏洞协同通常意味着：一个漏洞提供初始类型混淆或越界访问，另一个漏洞提供更稳定的内存原语，第三个漏洞用于沙箱逃逸或内核提权，最后在脚本层完成数据收集与外传。公开分析对其具体漏洞组合、利用顺序和失败处理有不同描述，本文不引用精确CVE编号。

纯脚本路线的优势是落盘少、迭代快、易于按目标定制，且可以把收集逻辑藏在看似正常的Web API调用中。它的限制同样明显：JavaScript运行在WebContent沙箱内，不能直接调用CoreBluetooth、CoreNFC、NearbyInteraction等特权框架；标签页关闭、进程被Jetsam回收或设备重启后，脚本层的驻留能力有限；若要长期驻留或访问受TCC保护的资源，仍需沙箱逃逸、内核能力或额外的原生桥接。

因此，DarkSword的风险不应被“无原生Payload”这句话稀释。它可能缩短驻留时间，但也可以在单次会话内完成高价值数据收集；它可能减少文件痕迹，但会在WebContent崩溃、JIT行为、网络请求和内存异常上留下另一类信号。防御者需要把“低落盘”与“低影响”分开判断。

### 2.4 七阶段能力对照
| 阶段 | Coruna（公开描述） | DarkSword（公开描述） | 防御关注点 | 证据强度 |
|---|---|---|---|---|
| 投递 | 定向链接、水坑或消息入口；具体渠道未公开 | Web入口为主；是否使用无线/消息投递未公开 | 入口暴露、用户交互、域名信誉 | 中/低 |
| 初始访问 | WebKit远程入口，WebContent内代码执行 | 多漏洞协同，JavaScriptCore/WebKit为主 | 补丁延迟、JIT、解析器 | 中 |
| 执行 | 分阶段原生载荷，PlasmaLoader衔接 | 以JavaScript逻辑为主，较少独立原生载荷 | 沙箱、代码签名、JIT | 中 |
| 持久化 | 可能使用launchd、trustcache或系统服务；细节未公开 | 主要依赖浏览器会话，长期驻留能力有限（推断） | launchd、签名、SSV、重启 | 低 |
| 提权 | 沙箱逃逸与内核提权，追求稳定控制 | 多漏洞组合，可能达到内核或等价能力 | PAC/PPL/KTRR/SPTM、内核攻击面 | 中 |
| 收集 | 文件、钥匙串、应用数据、麦克风/位置等，视权限而定 | 脚本可及数据为主；特权数据依赖逃逸（推断） | TCC、Data Protection、Keychain | 中 |
| 外传 | 原生网络栈、C2、分阶段下载 | HTTPS/WebSocket等Web通道为主 | 出站控制、DNS、代理、流量基线 | 中 |

### 2.5 能力差异的安全含义
Coruna更像“持久化平台”：一旦原生载荷落地，攻击者可以在较长时间内按需加载模块，逐步扩大收集范围。防御重点应放在沙箱逃逸后的主机侧异常、launchd/签名/系统卷完整性、以及长期外传行为。

DarkSword更像“短时任务”：在浏览器会话内完成尽可能多的操作，减少落盘与驻留。防御重点应放在WebKit/JIT攻击面、WebContent进程异常、会话隔离、以及浏览器到网络的出站行为。

两者都需要“入口补丁+沙箱+内核缓解+出站控制”的组合，但优先级不同。把两者都简化为“装个MDM、打补丁”会错过各自最脆弱的阶段。

## 三、资产分类与信任边界
### 3.1 六类资产
| 资产类 | 典型内容 | 失陷后果 | 关键控制 | 证据来源 |
|---|---|---|---|---|
| 用户数据 | 短信、通讯录、日历、照片、健康、位置、备忘录 | 隐私暴露、勒索、定向社工 | Data Protection、TCC、备份加密 | `sms.db`、`AddressBook.sqlitedb`、`Photos.sqlite`、`healthdb_secure.sqlite` |
| 凭证 | 密码、Passkey、OAuth令牌、Cookie、Wi-Fi PSK、VPN密钥 | 账号接管、横向移动 | Keychain访问控制、生物识别、会话撤销 | `keychain-2.db`、`Cookies.binarycookies`、App Group容器 |
| 密钥 | SEP-backed密钥、类密钥、iCloud Keychain、MDM身份证书 | 长期解密、身份伪造 | SEP、Secure Enclave、`ThisDeviceOnly` | `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`、`SecAccessControl` |
| 企业数据 | 邮件、文件、IM、内网应用、会议 | 数据泄露、合规责任 | 托管账户、per-app VPN、Managed Open In | MDM、ABM、应用配置 |
| 设备完整性 | 启动链、代码签名、TCC、MDM注册、越狱状态 | 所有本地控制失效 | 安全启动、SSV、AMFI、PAC/PPL/SPTM | `sysdiagnose`、`amfi`日志、完整性证明 |
| 网络位置 | Wi-Fi、VPN、热点、AirDrop/AWDL、蓝牙配对 | 内网跳板、中间人、横向扫描 | 网络分段、EAP-TLS、出站代理 | 流量、DNS、802.1X、MDM |

资产分类的关键不是列出更多文件名，而是明确“谁有权限读、读完能否恢复、泄露后能否撤销”。例如，照片的泄露不可撤销，凭证可以轮换，SEP密钥通常不可导出，设备完整性一旦破坏则只能重建。不同“可恢复性”应直接影响影响评分。

### 3.2 信任边界
```text
┌─────────────────────────────────────────────────────────────┐
│ 云与管理面：iCloud / APNs / MDM / ABM / 推送 / 备份          │
└───────────────────────────┬─────────────────────────────────┘
                            │ TLS、令牌、描述文件、备份协议
┌───────────────────────────▼─────────────────────────────────┐
│ 硬件根：Boot ROM → SEP/SEPOS → Secure Enclave → eSE         │
│ 保护：UID密钥、类密钥、生物模板、支付Applet、密钥 attestation │
└───────────────────────────┬─────────────────────────────────┘
                            │ 受控服务调用 / 加密通道
┌───────────────────────────▼─────────────────────────────────┐
│ 内核：XNU / KEXT / launchd / AMFI / Sandbox / TCC / MACF     │
│ 保护：代码签名、PAC、PPL、KTRR、SPTM/TXM、SSV                │
└───────────────────────────┬─────────────────────────────────┘
                            │ Mach IPC / XPC / 系统调用
┌───────────────────────────▼─────────────────────────────────┐
│ 用户态：daemon / App / Extension / WebContent / NetworkProcess│
│ 保护：entitlement、沙箱profile、TCC、Data Protection         │
└───────────────────────────┬─────────────────────────────────┘
                            │ USB / Wi-Fi / BT / NFC / UWB / 基带
┌───────────────────────────▼─────────────────────────────────┐
│ 外设与网络：配件、耳机、车机、AP、蜂窝网、近场终端            │
└─────────────────────────────────────────────────────────────┘
```

这张图的重点是“每一层都有独立的失败模式”。WebContent失陷只越过最内层应用边界；沙箱逃逸越过用户态隔离；内核失陷越过大多数本地控制；但SEP/SE仍是硬件边界。攻击链的每一段都可能被不同的控制点切断，防御不应只押注在一层。

### 3.3 边界穿越的控制点
从WebContent到系统，常见穿越机制包括：XPC/Mach服务调用、`IOSurface`共享内存、`task_for_pid`/`mach_vm_*`、驱动IOKit入口、launchd服务注册、以及文件系统/钥匙串访问。每一次穿越都对应一组可审计的控制点：entitlement是否允许、沙箱profile是否放行、TCC是否授权、代码签名是否有效、目标服务是否暴露。

从设备到网络，穿越机制包括：`NSURLSession`/`Network.framework`、DNS、代理、VPN、APNs、AirDrop/AWDL、蓝牙GATT、NFC、USB网络共享。企业通常只监控其中一部分（如DNS与代理），却忽略了本地无线链路与USB。威胁建模应把“未监控的穿越机制”单独列出，作为检测覆盖缺口。

从管理面到设备，穿越机制包括：MDM命令、描述文件、DDM声明、应用清单、证书信任设置、DNS代理、per-app VPN。管理面本身是高价值目标：攻陷MDM或滥用 enrollment，能一次性改变大量设备的信任配置。对管理面的风险评估应独立于终端风险评估。

## 四、攻击面清单
### 4.1 消息与邮件
iMessage与邮件是高级攻击最常见的入口之一，原因是它们在后台即可接收内容，且解析链复杂。iOS用`BlastDoor`把iMessage的解析与渲染隔离到独立服务，降低解析器漏洞直接进入SpringBoard的风险；`IMTranscoderAgent`处理媒体转码，`CoreMedia`、`ImageIO`、`QuickLook`等框架参与附件解析。短信/彩信落入`/var/mobile/Library/SMS/sms.db`，邮件附件可能经过`MessageUI`与WebKit远程内容加载。

攻击面包括：消息附件解析、链接预览、富文本/HTML渲染、媒体容器、联系人卡片、以及通知扩展。零点击链通常依赖解析器或解码器缺陷；一击链则依赖用户点击链接或打开附件。防御上，Lockdown Mode会阻止大多数消息附件类型、禁用部分链接预览与复杂Web技术；企业还可关闭“加载远程图像”、限制富文本、使用消息过滤与托管账户策略。

检测难点在于：解析发生在系统服务而非App进程，普通EDR看不到；崩溃日志可能只显示`BlastDoor`或`IMTranscoderAgent`异常。可观测信号包括：这些服务的重复崩溃、异常内存峰值、Jetsam事件、以及随后由`sharingd`/`rapportd`或浏览器产生的异常出站连接。

### 4.2 浏览器与WebContent
iOS的WebKit采用多进程架构：`com.apple.WebKit.WebContent`负责渲染与JavaScript执行，`com.apple.WebKit.NetworkProcess`负责网络，`com.apple.WebKit.GPUProcess`负责GPU/媒体。WebContent拥有JIT/动态代码签名相关entitlement和受限沙箱，具体entitlement名称随平台与版本变化；Safari、`WKWebView`、`SFSafariViewController`、Safari扩展与App Clip都可能成为入口。

攻击面包括：JavaScriptCore的JIT/类型混淆、WASM、DOM/CSS解析、媒体解码、GPU命令、IPC序列化、以及站点隔离不完整带来的跨站影响。Coruna与DarkSword都把WebKit作为核心入口，说明该面仍是高级攻击的高性价比目标。防御上，补丁速度是第一控制点；Lockdown Mode对JIT的限制会显著提高利用门槛；`WKWebView`应启用`limitsNavigationsToAppBoundDomains`（`WKAppBoundDomains`）与独立的数据存储，减少被诱导导航到恶意域的机会。

检测上，WebContent崩溃、JIT代码页异常、进程被Jetsam、以及“浏览器进程短时间多次重启”都是弱信号，但组合起来有价值。更强的信号来自网络侧：恶意域、罕见TLS指纹、GA/JS分发、以及WebContent/NetworkProcess的异常出站。

### 4.3 网络协议栈
iOS网络栈覆盖`NSURLSession`、`Network.framework`、HTTP/2、HTTP/3/QUIC、DNS、代理、VPN、mDNS/Bonjour与蜂窝基带。`mDNSResponder`、`nehelper`、`configd`、`CommCenter`等组件参与解析、策略与连接管理。企业网络中的恶意AP、 captive portal、DNS投毒、TLS拦截、代理自动配置（PAC）都可能改变流量路径。

攻击面包括：QUIC/HTTP解析器、DNS解析、证书验证、代理配置、VPN隧道、以及基带/运营商配置。高级攻击链通常不直接攻击网络栈，而是利用网络栈做投递、C2或中间人。Coruna的原生载荷可能使用系统网络API外传；DarkSword的脚本更可能直接使用`fetch`/WebSocket，因此网络侧看到的是浏览器进程的HTTPS流量。

防御上，ATS（App Transport Security）与证书校验是基线，但不应把ATS当作万能；企业应使用EAP-TLS Wi-Fi、受信CA、DNS过滤、出站代理与per-app VPN。检测上，DNS查询、TLS SNI、JA3/JA4、流量体积、长连接与心跳周期比单条IOC更稳健。

### 4.4 无线接口
无线接口包括Wi-Fi、蓝牙/BLE、NFC、UWB与AWDL。对应框架有`CoreBluetooth`（`CBCentralManager`、`CBPeripheral`、`CBService`、`CBCharacteristic`）、`CoreNFC`（`NFCNDEFReaderSession`、`NFCISO7816Tag`）、`NearbyInteraction`（`NISession`、`NINearbyPeerConfiguration`）以及私有的`MobileWiFi`、`BluetoothManager`、`WiFiPeerToPeer`、`Rapport`。系统侧常见组件包括`bluetoothd`、`wifid`、`nfcd`、`sharingd`、`rapportd`。

攻击面包括：恶意BLE外设、GATT服务仿冒、AirDrop/Handoff身份欺骗、NFC标签触发的URL/Universal Link、恶意Wi-Fi AP、UWB测距中继。对Coruna/DarkSword而言，无线更可能是投递或触发通道，而不是主要执行环境；公开资料未披露两者使用特定无线入口。防御上，MDM可关闭AirDrop、NFC、主机配对，Lockdown Mode会限制有线连接与部分无线行为；检测上，需要蓝牙/Wi-Fi侧的信标与终端日志，单靠MDM合规状态不够。本文第二篇将展开无线链路。

### 4.5 USB与配件
iOS通过`usbmuxd`（TCP 62078）与`lockdownd`提供USB配对、备份、调试与配件通信。配对记录位于`/var/root/Library/Lockdown/pair_records/`，包含`HostID`、`SystemBUID`、`HostCertificate`、`RootCertificate`、`DeviceCertificate`、`HostPrivateKey`等字段。`MobileDevice.framework`、`ExternalAccessory`、`IOAccessoryManager`、`IOUSBHostFamily`与iAP2协议参与配件识别与数据交换。

攻击面包括：恶意充电器、未受信计算机的配对请求、备份提取、开发者模式/调试接口、配件固件与USB-C替代模式。USB Restricted Mode在设备锁屏超过约一小时后阻断数据连接；`allowUSBRestrictedMode`（监督设备）可控制该行为，`allowHostPairing=false`可禁止非监督主机配对。企业应默认保持USB Restricted Mode开启，禁用开发者模式，使用数据阻断线，避免公共充电桩。

检测上，`lockdownd`日志、配对记录变化、锁屏状态下的USB连接、以及异常的`MobileBackup2`会话都值得关注。物理接触攻击往往不经过网络，网络侧检测完全失效。

### 4.6 MDM与配置
MDM/配置面包括`profiled`、`mdmd`、`ManagedConfiguration`、描述文件、DDM声明、证书信任、DNS代理、per-app VPN与应用清单。常见payload包括`com.apple.applicationaccess`（限制项）、`com.apple.wifi.managed`（Wi-Fi）、`com.apple.security.root`（根证书）、`com.apple.vpn.managed`（VPN）等。关键字段有`PayloadType`、`PayloadIdentifier`、`PayloadUUID`、`PayloadVersion`、`PayloadOrganization`、`PayloadRemovalDisallowed`。

攻击面包括：诱导用户安装恶意描述文件、伪造MDM enrollment、植入根CA、配置恶意DNS代理/VPN、通过Web Clip或企业应用分发投放载荷。配置文件的危险之处在于“一次安装，长期生效”，且用户往往不理解根CA与VPN配置的含义。防御上，企业应使用监督设备、ABM自动注册、限制描述文件安装、审计根CA与VPN配置、要求用户批准enrollment；个人应定期检查“VPN与设备管理”和“证书信任设置”。

检测上，配置清单基线、描述文件哈希、根CA指纹、DNS代理/VPN配置变化、以及MDM命令历史都比“设备合规=通过”更有意义。管理面失陷应按高 severity 事件处理，因为它能批量改变信任。

### 4.7 应用扩展
iOS扩展通过`NSExtension`与`NSExtensionPointIdentifier`注册，常见类型包括分享（`com.apple.share-services`）、键盘（`com.apple.keyboard-service`）、Safari（`com.apple.Safari.web-extension`）、网络（`com.apple.networkextension`）、文件提供者（`com.apple.fileprovider`）、小组件（`com.apple.widgetkit-extension`）与通知服务（`com.apple.usernotifications.service`）。相关entitlement包括`com.apple.security.application-groups`、`com.apple.developer.networking.networkextension`、`com.apple.developer.associated-domains`。

攻击面包括：键盘记录（需“完全访问”）、分享扩展读取剪贴板/文件、Safari扩展注入脚本、网络扩展观察/修改流量、文件提供者访问托管文件、通知服务处理远程内容。扩展通常继承宿主App的权限，但又有独立的沙箱与生命周期，容易被资产清单遗漏。

防御上，企业应限制可安装扩展、禁用不受信键盘的完全访问、使用托管App清单与per-app VPN、对Safari扩展做白名单。检测上，扩展进程的网络连接、剪贴板访问、以及异常的文件提供者读取都值得纳入基线。

### 4.8 备份
备份面包括本地备份（Finder/Apple Devices/`MobileBackup2`）与iCloud备份（`backupd`）。本地备份目录包含`Manifest.db`、`Manifest.plist`、`Status.plist`、`Info.plist`与`keybag`；备份是否加密决定了钥匙串与健康等数据的可读性。Data Protection类（`NSFileProtectionComplete`、`CompleteUnlessOpen`、`CompleteUntilFirstUserAuthentication`）与Keychain的可访问性属性（`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`等）决定了数据在锁屏与备份场景中的暴露。

攻击面包括：未加密本地备份被提取、iCloud账户被接管、备份被篡改、以及备份恢复过程中信任边界重置。防御上，使用加密本地备份、开启Advanced Data Protection、保护Apple Account（硬件安全密钥、强密码、受信设备审计）、限制iCloud备份（如策略允许）、并定期审查受信设备。

检测上，异常备份会话、备份大小突变、陌生主机的配对、以及iCloud账户的登录地点变化都值得关注。备份是“合法通道被滥用”的典型例子，单靠恶意文件扫描很难发现。

### 4.9 攻击面清单汇总
| 攻击面 | 入口 | 关键组件/API | 主要风险 | 可观测性 |
|---|---|---|---|---|
| 消息/邮件 | 附件、链接、富文本 | `BlastDoor`、`IMTranscoderAgent`、`CoreMedia`、`ImageIO` | 零点击解析、钓鱼 | 低（系统服务日志） |
| 浏览器 | 恶意站点、广告、WebView | `WebContent`、JSC/JIT、`WKWebView` | RCE、沙箱逃逸 | 中（崩溃/网络） |
| 网络 | AP、DNS、代理、VPN | `NSURLSession`、`Network.framework`、`mDNSResponder` | 中间人、C2 | 高（流量/DNS） |
| 无线 | BLE、NFC、AirDrop、UWB | `CoreBluetooth`、`CoreNFC`、`NearbyInteraction` | 投递、触发、跟踪 | 低（需专用嗅探） |
| USB | 充电器、主机、配件 | `usbmuxd`、`lockdownd`、`IOAccessoryManager` | 配对、备份、物理提取 | 中（主机日志） |
| MDM/配置 | 描述文件、enrollment | `profiled`、`mdmd`、`ManagedConfiguration` | 信任劫持、批量控制 | 中（配置基线） |
| 扩展 | 键盘、分享、Safari、网络 | `NSExtension`、NetworkExtension | 记录、注入、代理 | 中（进程/网络） |
| 备份 | 本地/iCloud | `backupd`、`MobileBackup2`、`Manifest.db` | 数据提取、篡改 | 中（备份审计） |

## 五、STRIDE与移动ATT&CK映射
### 5.1 STRIDE
| 威胁 | 移动场景表现 | 典型边界穿越 | 主要控制 | 检测信号 |
|---|---|---|---|---|
| Spoofing | 伪造AirDrop/Handoff身份、伪造MDM、仿冒App | 无线身份、管理面、Universal Link | 联系人验证、证书固定、enrollment审批 | 身份哈希异常、证书异常 |
| Tampering | 篡改配置、备份、内核内存、系统卷 | 描述文件、备份、内核 | SSV、签名、加密备份、完整性证明 | 配置漂移、备份哈希变化 |
| Repudiation | 设备侧缺少细粒度审计 | 日志/遥测 | 统一日志、MDM审计、网络日志 | 日志缺口本身 |
| Information disclosure | TCC绕过、剪贴板、通知、WebContent读取 | 沙箱、TCC、备份 | Data Protection、TCC、Lockdown | 异常读取、出站流量 |
| Denial of service | 内核崩溃、无线干扰、存储填满 | 内核、无线、存储 | 看门狗、资源限制、备份 | 崩溃/重启、Jetsam |
| Elevation of privilege | 沙箱逃逸、内核提权、签名绕过 | WebContent→内核→用户态 | PAC/PPL/SPTM、AMFI、最小权限 | 异常代码页、进程注入 |

STRIDE的价值在于提醒我们：高级攻击不只是“信息泄露”。拒绝服务可以掩盖取证，身份伪造可以绕过联系人验证，配置篡改可以持久化信任。风险评分应覆盖这些后果，而不是只计算数据条数。

### 5.2 移动ATT&CK
| 战术 | 技术示例 | Coruna相关性 | DarkSword相关性 | 遥测 |
|---|---|---|---|---|
| Initial Access | 投递恶意链接/附件（T1476类） | 高 | 高 | 域名、消息、点击 |
| Execution | Native API（T1575）、脚本执行（T1623类） | 高 | 高 | 进程、JIT、脚本行为 |
| Persistence | 启动项/计划任务（T1541/T1603类） | 高（原生载荷） | 低（会话型，推断） | launchd、文件、重启 |
| Privilege Escalation | 漏洞提权（T1068类） | 高 | 高 | 内核崩溃、PAC异常 |
| Defense Evasion | 混淆/无文件（T1627类） | 中 | 高 | 内存、脚本、日志缺口 |
| Credential Access | 钥匙串/输入捕获（T1634/T1417类） | 高 | 中 | Keychain、键盘、TCC |
| Discovery | 系统/网络信息（T1426/T1422类） | 高 | 高 | 设备指纹、网络探测 |
| Collection | 本地数据、屏幕、音频、位置（T1409/T1513/T1429/T1430类） | 高 | 中高 | TCC、文件、传感器 |
| Exfiltration | C2/Web服务（T1646/T1567类） | 高 | 高 | 出站、DNS、体积 |
| Command and Control | 应用层协议（T1437类） | 高 | 高 | TLS/WebSocket、心跳 |

ATT&CK是行为分类，不是漏洞库。把Coruna/DarkSword映射到ATT&CK时，应把“公开证据”和“推断”分开，避免用技术编号制造精确感。映射的真正用途是生成检测假设：例如，若担心DarkSword的脚本收集，就应优先建设WebContent到网络的出站基线，而不是寻找某个特定文件。

## 六、攻击路径图
### 6.1 Coruna路径
```text
[1] 定向投递（链接/消息/水坑，具体渠道公开资料未披露）
        │
        ▼
[2] Safari/WebContent 加载恶意页面
        │  JSC/JIT 或解析器缺陷
        ▼
[3] WebContent 内代码执行
        │  绕过/利用沙箱IPC、IOSurface、XPC
        ▼
[4] 沙箱逃逸
        │  内核漏洞或驱动入口
        ▼
[5] 内核读写/等价能力
        │  加载器落地
        ▼
[6] PlasmaLoader（分阶段载荷）
        │  launchd/trustcache/系统服务（推断）
        ▼
[7] 持久化与模块加载
        │
        ├── 收集：文件/钥匙串/应用数据/传感器（视权限）
        └── 外传：C2/HTTPS/分阶段下载
```

关键咽喉点：浏览器补丁、JIT限制、WebContent沙箱、内核缓解（PAC/PPL/SPTM）、代码签名/SSV、launchd持久化、出站网络。Coruna的“长驻留”意味着第6–7阶段是最有价值的检测窗口；如果只监控初始访问，容易在载荷落地后失去可见性。

### 6.2 DarkSword路径
```text
[1] Web入口（恶意站点/广告/被篡改页面）
        │
        ▼
[2] WebContent 内多漏洞协同
        │  类型混淆 → 内存原语 → 稳定读写
        ▼
[3] 沙箱逃逸/内核能力（公开细节有限）
        │
        ▼
[4] JavaScript 驱动的收集
        │  DOM/存储/Cookie/可及文件（推断）
        ▼
[5] Web通道外传
        │  fetch/WebSocket/HTTPS
        ▼
[6] 会话结束或进程回收 → 能力衰减
```

关键咽喉点：JIT攻击面、站点隔离、WebContent进程回收、TCC/沙箱、出站网络。DarkSword的“短时任务”意味着检测窗口可能只有数分钟到数小时；如果日志保留期太短、或只依赖每日合规检查，就会错过。

### 6.3 关键咽喉点
| 咽喉点 | 对Coruna的价值 | 对DarkSword的价值 | 可观测性 | 控制成本 |
|---|---|---|---|---|
| 浏览器补丁 | 高 | 高 | 版本合规 | 低 |
| JIT限制/Lockdown | 高 | 高 | 配置状态 | 低 |
| WebContent沙箱 | 高 | 高 | 崩溃/进程 | 中 |
| 内核缓解 | 高 | 高 | 崩溃/panic | 高 |
| 持久化检测 | 高 | 低 | launchd/文件 | 中 |
| 出站控制 | 高 | 高 | 网络/DNS | 中 |
| 身份与凭证 | 高 | 中 | 登录/令牌 | 低 |

“控制成本低、对两条链都有效”的咽喉点应优先投入：补丁、JIT限制、出站控制、身份撤销。内核缓解成本高，但它是防止“单次浏览器漏洞变成全设备控制”的关键。

## 七、风险量化模型
### 7.1 四因子
本文使用四个因子：

- L（Likelihood，可能性，1–5）：目标暴露度、攻击者动机、入口可达性、必要前置条件。
- I（Impact，影响，1–5）：资产敏感性、影响范围、可恢复性、合规/业务后果。
- X（Exploitability，可利用性，1–5）：利用可靠性、所需权限、用户交互、公开工具成熟度。
- D（Detection coverage，检测覆盖，1–5）：5表示有跨阶段、经过验证的检测；1表示基本不可见。

公式：

`R = 4 × L × I × (X/5) × ((6-D)/5)`

R的范围是0–100。乘以4是为了把最大值归一化到100：L=I=X=5、D=1时，R=4×5×5×1×1=100。分级建议：R≥70为P0，50–69为P1，30–49为P2，20–29为P3，<20为P4。分数不是概率，而是相对优先级；它应随遥测与事件复盘更新。

### 7.2 评分锚点
| 因子 | 1 | 3 | 5 | 说明 |
|---|---|---|---|---|
| L | 几乎不接触该入口 | 常规企业暴露 | 高价值定向、入口必然可达 | 结合行业与角色 |
| I | 可撤销的少量数据 | 部门级数据/凭证 | 全设备完整性/高管/密钥 | 关注不可恢复性 |
| X | 需物理接触且极不稳定 | 需点击、部分缓解 | 远程、稳定、可复用 | 结合补丁与Lockdown |
| D | 无日志/无告警 | 有日志但需人工关联 | 跨阶段、低误报、已演练 | 以验证结果为准 |

### 7.3 公式与示例
示例一：高价值目标、未启用Lockdown Mode、补丁滞后30天、仅有网络日志。Coruna场景取L=4、I=5、X=5、D=2，则R=4×4×5×1×0.8=64，P1（接近P0）。若把D提升到3（增加WebContent崩溃与出站关联），R=4×4×5×1×0.6=48，降为P2；若同时把补丁延迟压到7天，X降为4，R=38.4。

示例二：普通员工、最新系统、启用Lockdown Mode、有DNS与代理日志。DarkSword场景取L=2、I=4、X=3、D=3，则R=4×2×4×0.6×0.6=11.52，P3。若该员工是财务/法务高价值角色，L升到3，R=17.28，仍为P3，但应进入重点观察名单。

这两个例子说明：同一攻击链的分数可以相差数倍，差异来自资产、暴露、补丁与检测，而不是攻击链的名字。评分时应把假设写在表格备注里，避免“64分”脱离上下文。

### 7.4 置信度与敏感性
建议为每个分数记录置信度（高/中/低）与关键假设。对L和I做±1的敏感性分析：如果分数跨越优先级边界，应补充证据而不是强行取整。对D的评估应以最近一次演练/真实告警为准，不能以“工具已部署”代替“检测已验证”。

模型不包含攻击成本、归因概率与威慑因素。若需要投资回报分析，可另加“攻击者成本”与“控制成本”两个维度，但不要把它们混入同一分数，否则难以解释。

## 八、两套攻击链的风险评分与优先级
### 8.1 场景评分
以下评分为示例环境：中大型企业、混合办公、受监督设备为主、补丁延迟中位数14天、具备DNS/代理日志但缺少终端EDR。分数仅用于方法演示。

| ID | 场景 | L | I | X | D | R | 优先级 | 备注 |
|---|---|---|---|---|---|---|---|---|
| S1 | 高价值目标遇Coruna完整链 | 4 | 5 | 5 | 2 | 64 | P1 | 原生载荷、长驻留 |
| S2 | 普通员工遇DarkSword纯JS链 | 3 | 4 | 4 | 2 | 30.7 | P2 | 会话型、低落盘 |
| S3 | 消息附件零点击解析链（未归因） | 2 | 5 | 4 | 2 | 25.6 | P3 | 入口隐蔽 |
| S4 | 恶意配置描述文件/伪造MDM | 3 | 5 | 3 | 3 | 21.6 | P3 | 信任劫持 |
| S5 | 公共Wi-Fi/captive portal钓鱼 | 4 | 4 | 3 | 3 | 23.0 | P3 | 用户交互 |
| S6 | NFC标签触发URL→浏览器 | 3 | 4 | 4 | 3 | 23.0 | P3 | 需用户点击 |
| S7 | 恶意USB主机/备份提取 | 1 | 5 | 4 | 3 | 9.6 | P4 | 需物理接触 |
| S8 | 恶意键盘/分享扩展 | 3 | 3 | 3 | 2 | 17.3 | P4 | 需用户授权 |
| S9 | DarkSword C2外传阶段 | 4 | 5 | 4 | 2 | 51.2 | P1 | 出站可见性关键 |
| S10 | iCloud账户接管→备份 | 2 | 5 | 3 | 3 | 14.4 | P4 | 身份因素 |

### 8.2 Coruna与DarkSword对比
| 阶段 | Coruna（示例R） | DarkSword（示例R） | 差异解读 |
|---|---|---|---|
| 初始访问 | 48–64 | 25–35 | 两者都依赖WebKit，Coruna更常被用于高价值定向 |
| 执行 | 60+ | 30–45 | 原生载荷能力更强，但痕迹更多 |
| 持久化 | 50+ | <20 | Coruna的核心优势；DarkSword受会话限制 |
| 提权 | 60+ | 45+ | 两者都可能达到内核/等价能力 |
| 收集 | 60+ | 25–40 | 特权API与TCC决定差距 |
| 外传 | 50+ | 40+ | 都依赖出站通道，原生载荷更灵活 |
| 检测覆盖 | 低–中 | 低–中 | 都缺少跨阶段关联 |

### 8.3 优先级解释
Coruna应优先处理“持久化+收集”阶段：检查launchd异常、系统卷完整性、签名/信任缓存、以及长期出站。DarkSword应优先处理“执行+外传”阶段：缩短WebKit补丁窗口、限制JIT、隔离WebView、建立浏览器出站基线。

如果资源有限，先做对所有链都有效的控制：补丁、Lockdown Mode、出站代理/DNS、Apple Account与MDM审计。然后再做针对性控制：Coruna的持久化检测、DarkSword的JIT/会话检测。这样不会陷入“追样本”的被动局面。

## 九、攻击面收敛与检测覆盖缺口
### 9.1 收敛原则
攻击面收敛不是“把所有功能都关掉”，而是按角色与风险分级，做到“默认最小、例外可审计”。可操作的原则包括：

- 默认关闭未使用的AirDrop、NFC、蓝牙、UWB与个人热点；高敏感角色使用更严格的基线。
- 统一浏览器与WebView策略：禁止不受信导航、禁用不必要的JS扩展、限制JIT（高敏感角色）。
- 对USB配件与主机配对实施白名单；保持USB Restricted Mode开启。
- 描述文件与根CA集中管理，禁止用户安装未审批配置；MDM enrollment要求审批与资产绑定。
- 备份加密、Apple Account强认证、受信设备定期审计。
- 应用扩展按功能白名单，键盘“完全访问”仅授予必要应用。

收敛的度量应包含“暴露面单元数”（如允许AirDrop的设备数、允许NFC的设备数、可安装扩展数）与“例外数量”。没有度量的收敛很容易反弹。

### 9.2 检测覆盖缺口
| 阶段 | 可观测信号 | 主要缺口 | 补偿控制 |
|---|---|---|---|
| 投递 | 域名、消息、点击、NFC/AirDrop事件 | 加密消息与本地无线不可见 | 域名情报、MDM限制、用户报告 |
| 初始访问 | WebContent崩溃、JIT异常、解析器崩溃 | iOS缺少内核级EDR | 补丁、Lockdown、崩溃聚合 |
| 执行 | 进程树、代码页、内存异常 | 沙箱内脚本低可见 | 网络基线、JIT限制 |
| 持久化 | launchd、文件、签名、系统卷 | SSV下持久化更隐蔽 | 完整性证明、重启基线 |
| 提权 | panic、PAC异常、内核崩溃 | 日志保留短、符号化难 | 集中崩溃分析、版本对比 |
| 收集 | TCC、Keychain、文件、传感器 | 系统服务代用户访问 | TCC审计、隐私指示器 |
| 外传 | DNS、TLS、流量、心跳 | 加密与域前置 | 出站代理、JA4、体积基线 |

## 十、企业与个人处置清单
### 10.1 企业30/60/90天
0–30天：完成iOS资产与MDM注册盘点；把补丁延迟压到可接受范围；对高敏感角色关闭AirDrop/NFC/主机配对；审计描述文件、根CA、VPN/DNS代理；启用统一日志与崩溃聚合；建立Apple Threat Notifications的接收与处置流程。

31–60天：试点Lockdown Mode（高敏感角色）；为WebView启用App-Bound Domains与非持久化数据存储；部署DNS过滤、出站代理与per-app VPN；限制键盘完全访问与Safari扩展；加密本地备份并评估Advanced Data Protection；把MDM合规与真实检测分离。

61–90天：建设跨阶段检测（WebContent崩溃→异常出站→凭证使用）；开展针对Coruna/DarkSword的桌面演练；验证USB Restricted Mode与配对白名单；建立配置漂移告警；把无线暴露纳入季度评估；对高价值目标做设备更换与凭证轮换预案。

### 10.2 个人
- 保持系统与Safari/WebKit最新，不安装来源不明的描述文件；高风险人群评估Lockdown Mode。
- AirDrop设为“仅联系人”或关闭，关闭“将设备靠近以共享”（NameDrop）；不需要时关闭Handoff与Universal Clipboard。
- 定期检查“VPN与设备管理”和“证书信任设置”；保持USB Restricted Mode开启，避免公共充电桩与未知电脑。
- 使用强密码与Stolen Device Protection；为Apple Account启用硬件安全密钥；高风险人群开启Advanced Data Protection与Contact Key Verification。
- 不需要时关闭NFC/蓝牙；检查Wallet中的Express Mode卡片，移除不用的快捷卡。
- 重启不能清除内核级驻留，但能缩短部分内存攻击的窗口；关注Apple Threat Notifications并按其指引处置。

### 10.3 事件响应
怀疑设备被高级攻击链命中时，第一步不是“删App/重启”，而是保留证据：触发sysdiagnose、记录系统版本与补丁状态、保存统一日志与崩溃报告、导出MDM配置与网络日志。随后隔离网络（关闭Wi-Fi/蜂窝/蓝牙），但不要立即抹除设备，除非已确认数据备份与法律要求。
凭证处置应与设备处置并行：撤销OAuth/会话令牌、轮换高风险密码、检查iCloud受信设备与App专用密码、审查MDM/ABM管理员活动。若确认内核或持久化层失陷，建议更换设备而不是仅重装系统；重装可能无法覆盖被篡改的固件/配件或残留的信任关系。
最后，按合规要求通知相关方，保留时间线与决策记录。高级攻击的取证往往依赖外部专业能力，企业内部应提前约定升级路径，而不是事发后再找资源。

## 结语
Coruna与DarkSword的对比提醒我们：高级iOS攻击的差异不只在漏洞，更在“获得执行之后如何维持、如何收集、如何外传”。威胁建模的价值，是把这些差异转化为可比较的资产暴露、边界控制与检测覆盖，而不是追逐样本名称。

对企业而言，最有效的投入仍然是补丁速度、JIT/沙箱收紧、出站控制、身份与配置审计；对个人而言，最有效的投入是更新、减少不必要的共享面、保护Apple Account与备份。无线与USB不是主战场，但它们提供了绕过网络防线的旁路，值得单独建模。

风险分数不是结论，而是讨论的起点。真正需要持续回答的问题是：我们能否在攻击链的关键咽喉点上，以可验证的方式看到并阻断行为？如果答案是否定的，那么再多的工具清单也只是安慰。

## 参考资料
- Apple Platform Security Guide：https://support.apple.com/guide/security/welcome/web
- Apple：About Lockdown Mode：https://support.apple.com/en-us/105120
- Apple Developer：Restrictions（MDM）：https://developer.apple.com/documentation/devicemanagement/restrictions
