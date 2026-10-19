# iOS蓝牙与近场通信攻击面分析-Coruna与DarkSword生态中无线链路的安全边界

> 分析范围：iOS的蓝牙/BLE、Wi-Fi点对点、NFC、UWB与相关系统服务。
> 事实边界：Coruna与DarkSword的公开分析主要围绕WebKit、JavaScript与分阶段载荷展开，未披露具体的无线投递或无线外传细节。本文把无线角色分为“公开事实”“架构推断”“低置信度假设”，不把推断写成事件。

## 摘要

移动攻击链通常从消息、浏览器或应用开始，无线接口看似只是“连接外设”的辅助功能。但从系统安全角度看，蓝牙、Wi-Fi点对点、NFC与UWB共同构成了一个绕过传统网络边界的近场攻击面：它们可以在没有IP路由、没有企业代理、甚至没有用户主动打开浏览器的情况下完成发现、触发与数据交换。对Coruna这类具备原生载荷的链条，无线可能成为投递前导或外传旁路；对DarkSword这类纯JavaScript链条，无线更可能只是触发入口，因为WebContent沙箱不能直接调用CoreBluetooth、CoreNFC或NearbyInteraction。

本文先描述iOS无线栈的硬件、内核、守护进程、框架与权限边界，再分别分析BLE/GATT、AirDrop/Continuity/Handoff、NFC/Apple Pay/Express Mode与UWB的攻击模型。随后给出Coruna/DarkSword无线角色的推断矩阵、无线链路风险矩阵，以及可落地的MDM、配置描述文件、日志与检测方案。

核心判断是：无线不是Coruna/DarkSword的主战场，但它是高价值目标的旁路与高影响支付场景的主战场。企业应把NFC/Express Mode与AirDrop/Continuity列为独立风险域，而不是把它们淹没在“移动设备安全”总项里；个人应优先减少不必要的可发现性与免认证支付面。

**关键词**：iOS；蓝牙；BLE；GATT；NFC；Apple Pay；Express Mode；AirDrop；Handoff；UWB；Coruna；DarkSword；无线攻击面

## 引言

iOS的无线栈是“系统服务+私有框架+硬件控制器+固件”的复合体。应用开发者看到的CoreBluetooth与CoreNFC只是最上层的一小部分；真正的攻击面分布在广播、连接、配对、GATT、AWDL、NFC路由、Secure Element与UWB测距等多个层次。把这些层次混为一谈，会导致两类错误：把“应用能扫到BLE”当成“应用能控制蓝牙”，或把“NFC支付很安全”当成“NFC没有攻击面”。

Coruna与DarkSword的公开资料把注意力集中在WebKit与载荷上，这是合理的：这两条链的核心价值在于远程代码执行与后续控制，而不是近场无线。但威胁建模不能因为“主路径不在这里”就忽略旁路。攻击者可以选择更弱的入口，也可以在主入口被封锁后改用近场触发；防御者则需要知道哪些无线能力是“默认可发现、无需认证、可被物理接近利用”的。

本文的推断遵循三条规则：第一，只有公开分析明确描述的能力才作为事实；第二，基于iOS沙箱、TCC、entitlement与硬件边界的推论标注为“推断”；第三，无法从公开资料确认的具体事件、样本行为与CVE一律不写。这样既能讨论Coruna/DarkSword，又不会制造虚假的战例。

## 一、无线接口为何是高级攻击链的备选通道

### 1.1 入口经济学

高级攻击者选择入口时，会比较三类成本：取得初始执行的成本、被发现的概率、以及失败后的可重试性。WebKit入口的优势是远程、可规模化、可在浏览器内完成多阶段利用；劣势是补丁快、检测多、需要目标访问页面。无线入口的优势是物理接近即可尝试、部分协议在系统层自动处理、企业网络监控覆盖不到；劣势是距离受限、需要特定硬件、带宽低、且iOS的权限与配对流程会打断自动化。

对Coruna/DarkSword这类“浏览器中心”的链条，无线更合理的角色是“把目标带到浏览器”：NFC标签写入URL、AirDrop发送一个会被Safari/Quick Look打开的文件、Wi-Fi captive portal诱导登录。这些路径都需要用户动作，不能替代WebKit零点击链，但可以绕过“不要点陌生短信链接”的单一防线。

### 1.2 无线链路的特殊性

无线链路不经过企业的DNS、代理与CASB，因此传统网络检测看不到。BLE广播可以被动收集，NFC在几厘米内完成，AWDL在设备之间直接建链，UWB在物理层测距。它们的安全边界更多依赖iOS的权限弹窗、配对确认、联系人验证与硬件隔离，而不是企业边界设备。

无线链路的另一个特殊性是“协议层与系统层耦合”。BLE的配对失败会影响GATT访问，NFC的标签类型决定CoreNFC会话的路由，AirDrop的发现依赖BLE而传输依赖AWDL，Handoff的广播用AES-256-GCM加密但依赖iCloud身份。攻击面不是单一协议，而是协议之间的状态机与信任传递。

### 1.3 攻击阶段映射

```text
投递          初始访问        执行          外传
  │              │              │              │
  ├─ NFC标签 ────┤              │              │
  ├─ AirDrop ────┤              │              │
  ├─ Wi-Fi AP ───┤              │              │
  ├─ BLE广播 ────┘              │              │
  │                             │              │
  └──────────────► 浏览器/消息 ─┴─► 漏洞链 ────┘
                                   │
                                   ├─ 原生载荷：可调用无线API（推断）
                                   └─ 纯JS：受WebContent沙箱限制（推断）
```

这张图的关键是“无线只管到门口”。除了原生载荷可以直接调用无线框架外，无线本身很少能完成代码执行；它提供的是投递、触发与低带宽外传。把无线当成“远程RCE入口”会高估它；把无线当成“完全无关”会低估它在物理接近场景中的价值。

## 二、iOS无线栈架构与权限边界

### 2.1 硬件与固件

iPhone的无线子系统包括Wi-Fi/蓝牙组合芯片、独立的NFC控制器、U1/U2超宽带芯片，以及蜂窝基带。Wi-Fi与蓝牙共享射频与天线资源，NFC控制器负责在应用处理器、Secure Element与场端之间路由，UWB负责精细测距。各控制器运行厂商/Apple固件，主处理器通过受控接口访问，不能像访问普通外设一样直接读写射频寄存器。

这种架构带来两个安全含义。第一，固件漏洞的影响可能跨协议：Wi-Fi/蓝牙组合芯片的缺陷可能同时影响两个栈，但利用路径与可达性不同。第二，硬件隔离是真实边界：NFC支付凭证保存在Secure Element的Java Card applet中，应用处理器即使被攻陷也不能直接读出PAN；UWB的测距密钥与Secure Element/SEP的配合也不是纯软件可以伪造的。

### 2.2 内核与用户态组件

内核侧通过`IO80211Family`、`IOBluetoothFamily`、`IOUSBHostFamily`等驱动族暴露网络与蓝牙接口；NFC与UWB有各自的控制器驱动与路由机制。用户态常见组件包括`bluetoothd`（蓝牙栈）、`wifid`（Wi-Fi管理）、`nfcd`（NFC）、`sharingd`（AirDrop/分享）、`rapportd`（Continuity/Handoff）、`passd`（Wallet/PassKit相关）、`SpringBoard`与`backboardd`（UI与事件）。组件名称与职责随iOS版本变化，分析时应以实际系统镜像为准。

私有框架`MobileWiFi`、`BluetoothManager`、`WiFiPeerToPeer`、`Rapport`、`NearField`为系统应用与特权服务提供更底层的能力；公开框架`CoreBluetooth`、`CoreNFC`、`NearbyInteraction`、`NetworkExtension`则面向第三方应用。公开框架的能力受到TCC、entitlement与前台状态约束，私有框架的能力则取决于调用者的签名与沙箱。

### 2.3 框架与API

CoreBluetooth的核心对象是`CBCentralManager`（中心）、`CBPeripheral`（外设）、`CBService`、`CBCharacteristic`、`CBDescriptor`与`CBUUID`。外设侧使用`CBPeripheralManager`、`CBMutableService`、`CBMutableCharacteristic`与`CBATTRequest`。连接参数、后台恢复与L2CAP分别由`CBConnectPeripheralOptionNotifyOnDisconnectionKey`、`CBCentralManagerOptionRestoreIdentifierKey`与`CBL2CAPChannel`等接口控制。

CoreNFC提供`NFCNDEFReaderSession`（NDEF）、`NFCTagReaderSession`（ISO 7816/15693/18092）、`NFCISO7816Tag`、`NFCMiFareTag`、`NFCISO15693Tag`、`NFCFeliCaTag`与`NFCISO7816APDU`。会话需要`NFCReaderUsageDescription`与相应entitlement；标签访问通常要求应用在前台，后台标签读取只处理NDEF并弹出系统通知。

NearbyInteraction提供`NISession`、`NINearbyPeerConfiguration`、`NINearbyAccessoryConfiguration`、`NIDiscoveryToken`、`NINearbyObject`与`NISessionDelegate`；使用时需要`NSNearbyInteractionUsageDescription`，且对端/配件需要支持相应的发现与测距流程。

### 2.4 权限与entitlement

| 能力 | Info.plist/权限 | entitlement/系统限制 | 边界 |
|---|---|---|---|
| 蓝牙 | `NSBluetoothAlwaysUsageDescription` | TCC `kTCCServiceBluetoothAlways`；后台模式`bluetooth-central`/`bluetooth-peripheral` | 不能获取对端MAC；不能绕过配对 |
| 本地网络 | `NSLocalNetworkUsageDescription`、`NSBonjourServices` | TCC `kTCCServiceLocalNetwork` | 首次访问需授权；影响Bonjour/AWDL附近发现 |
| Wi-Fi信息 | `NSLocationWhenInUseUsageDescription` | `com.apple.developer.networking.wifi-info` | SSID/BSSID访问受位置与entitlement限制 |
| 热点配置 | — | `com.apple.developer.networking.HotspotConfiguration` | 只能配置/加入，不等于任意Wi-Fi控制 |
| NFC读取 | `NFCReaderUsageDescription` | `com.apple.developer.nfc.readersession.formats`；ISO7816/FeliCa需对应select-identifiers/systemcodes | 需前台会话；标签类型受限 |
| NFC & SE平台 | — | Apple授予的专用entitlement（名称未公开） | 仅授权开发者；applet需审核 |
| UWB | `NSNearbyInteractionUsageDescription` | 系统/配件支持与用户授权 | 需要发现令牌或MFi配件 |
| 网络扩展 | — | `com.apple.developer.networking.networkextension` | 需配置与用户批准；受监管限制 |

### 2.5 架构图

```text
┌──────────────────────────────────────────────────────────────┐
│ App / Extension：CoreBluetooth / CoreNFC / NearbyInteraction │
│ 约束：TCC、entitlement、前台状态、App Sandbox                 │
└───────────────┬──────────────────────────────┬───────────────┘
                │ XPC                          │ XPC
┌───────────────▼──────────────┐  ┌────────────▼───────────────┐
│ bluetoothd / wifid           │  │ nfcd / sharingd / rapportd │
│ GATT、L2CAP、配对、AWDL发现  │  │ NFC路由、AirDrop、Handoff  │
└───────────────┬──────────────┘  └────────────┬───────────────┘
                │ HCI/驱动                      │ 控制器路由
┌───────────────▼──────────────┐  ┌────────────▼───────────────┐
│ Wi-Fi/BT组合芯片 + 固件       │  │ NFC控制器 + Secure Element │
│ 802.11/BLE/BR/EDR            │  │ ISO14443/7816、EMV applet  │
└───────────────┬──────────────┘  └────────────┬───────────────┘
                │ 射频                          │ 近场耦合
┌───────────────▼──────────────┐  ┌────────────▼───────────────┐
│ AP、BLE外设、AirDrop对端      │  │ POS终端、门禁、交通闸机     │
└──────────────────────────────┘  └────────────────────────────┘
                │
        ┌───────▼────────┐
        │ U1/U2 UWB芯片  │
        │ 精细测距/空间感知│
        └────────────────┘
```

## 三、BLE/GATT攻击模型

### 3.1 广播层

BLE外设通过广播信道发送广告包，Legacy Advertising的有效载荷通常为31字节，可包含Flags、16-bit/128-bit Service UUID、Local Name、TX Power与Manufacturer Specific Data。iOS应用通过`CBAdvertisementDataLocalNameKey`、`CBAdvertisementDataServiceUUIDsKey`、`CBAdvertisementDataManufacturerDataKey`等键读取；扫描时可用`CBCentralManagerScanOptionAllowDuplicatesKey`提高回调频率，但后台扫描会被系统限流。

广播层的攻击主要是“诱骗”和“跟踪”。攻击者可以伪造知名服务UUID、复制设备名称、仿冒Apple Continuity的厂商字段（Apple公司ID为`0x004C`），诱导应用或用户连接；也可以利用固定广播特征做长期跟踪。iOS使用可解析私有地址（RPA）与身份解析密钥（IRK）降低跟踪，应用拿到的`CBPeripheral.identifier`是App范围的UUID而非MAC地址；但广播中的自定义字段仍可能泄露信息。

公开研究曾发现Apple Continuity广播（AirDrop、Nearby等）包含短身份哈希，可能被枚举出电话号码/邮箱；Apple后续通过默认“仅联系人”、限缩广播与身份验证降低暴露。这类历史案例说明：广播层的隐私风险往往来自“协议设计中的可关联字段”，而不是蓝牙链路加密本身。

### 3.2 连接与配对

BLE连接建立后，central与peripheral按连接间隔（最小7.5 ms，最大4 s）通信；ATT MTU默认23字节，启用Data Length Extension后可协商到更大的载荷，iOS通过`CBPeripheral.maximumWriteValueLength(for:)`暴露当前上限。连接参数、监督超时与PHY选择会影响吞吐、延迟与可检测性。

配对分为LE Legacy与LE Secure Connections（LESC）。LESC使用ECDH P-256、AES-CCM与HMAC-SHA-256，支持Just Works、Passkey、Numeric Comparison与OOB。Just Works没有MITM保护，适合无输入能力的配件，但不能抵御主动中间人；Passkey/Numeric Comparison需要用户确认，安全性更高但依赖UI。配对后生成LTK/IRK/CSRK等密钥，绑定信息由系统安全存储。

| 配对方式 | 用户交互 | MITM保护 | 典型场景 | 风险 |
|---|---|---|---|---|
| Just Works | 确认连接 | 无 | 简单外设 | 主动MITM、配对降级 |
| Passkey | 输入/确认6位数字 | 有 | 键盘、车机 | 用户误确认、界面欺骗 |
| Numeric Comparison | 双方数字一致 | 有 | 有屏设备 | 社会工程 |
| OOB | 带外通道 | 有 | 配件配对 | OOB通道被控 |
| LE Legacy | 取决于IO能力 | 较弱 | 旧配件 | 被动嗅探、降级 |

iOS不会向第三方应用暴露配对密钥；`CBPeripheralManager`也不提供底层配对API。攻击者若想滥用配对，通常需要伪造外设、诱导用户确认，或先获得系统权限后读取绑定信息。对企业而言，禁用不必要的外设配对、使用受管配件、避免在敏感区域开放可发现性，比“只信任已知UUID”更有效。

### 3.3 GATT服务

GATT是BLE上最常被攻击的应用层。外设暴露服务、特征与描述符；central通过`discoverServices`、`discoverCharacteristics`、`discoverDescriptors`枚举，通过`readValue`、`writeValue`、`setNotifyValue`交互。标准服务包括Battery（`0x180F`）、Device Information（`0x180A`）、HID over GATT（`0x1812`）与Current Time（`0x1805`）；Apple的ANCS使用`7905F431-B5CE-4E99-A40F-4B1E122D00D0`，AMS使用`89D3502B-0F36-433A-8EF4-C502AD55F8DC`。

攻击模型包括：仿冒已知服务UUID诱导应用写入敏感数据；利用可写特征注入命令；通过通知特征泄露状态；利用HID over GATT伪造键盘输入（需要配对与用户授权）；利用ANCS获取通知元数据（需要配对与授权）；通过L2CAP CoC建立更高吞吐通道（需要连接与PSM）。iOS的TCC与配对流程会阻止大多数“无交互”滥用，但恶意配件仍可在用户信任后长期驻留。

检测GATT攻击不能只看UUID，因为UUID可以伪造。更有价值的信号是：新出现的外设、异常的服务组合、与已知配件指纹不一致的GATT表、连接后立即请求通知/写入、以及应用在后台频繁重连。企业可通过MDM限制配件与后台蓝牙，个人应删除不用的配对并关闭不必要的外设广播。

### 3.4 后台、L2CAP与状态恢复

iOS允许应用声明`bluetooth-central`或`bluetooth-peripheral`后台模式。central可在后台扫描特定服务、接收连接与通知；peripheral可在后台广播，但广播内容与可发现性受系统限制。`CBCentralManagerOptionRestoreIdentifierKey`与`willRestoreState`让应用在系统重启后恢复会话，这也意味着长期存在的蓝牙状态可能跨应用生命周期。

`CBL2CAPChannel`提供面向连接的L2CAP通道，适合较高吞吐的数据传输；它仍然建立在BLE连接与配对之上，不能绕过TCC或配对。对攻击者而言，L2CAP适合在受信配件中传输配置或数据，但不适合作为“无感知外传”的通用通道，因为连接、配对与前台/后台状态都会留下痕迹。

## 四、AirDrop/Continuity/Handoff攻击面

### 4.1 AirDrop

AirDrop使用BLE做发现、Apple点对点Wi-Fi（AWDL）做传输。发送端在BLE广播中携带AirDrop短身份哈希；接收端在“仅联系人”模式下把哈希与通讯录比对，匹配后才通过点对点Wi-Fi回应身份。传输使用TLS，双方交换iCloud身份证书，接收端显示发送者姓名/头像并要求接受。设备使用随机MAC与TSF偏移降低跟踪。

攻击面包括：身份哈希枚举（历史研究）、恶意文件投递、拒绝服务、以及“Everyone”模式下的陌生设备骚扰。AirDrop的TLS与用户接受步骤降低了远程代码执行的直接风险，但文件仍可能被不支持的类型处理链解析；若接收端用Safari/Quick Look打开恶意文件，攻击面就转移到WebKit/解析器。Coruna/DarkSword是否使用AirDrop投递，公开资料未披露；从架构上看，这是一条“需要用户接受”的低置信度路径。

iOS 16.2后“所有人”模式限时10分钟；iOS 17的NameDrop通过设备靠近交换联系人信息，可在“将设备靠近以共享”中关闭。企业可用`allowAirDrop=false`（监督设备）直接关闭AirDrop。

### 4.2 Handoff与Universal Clipboard

Handoff使用BLE 4.2带外配对（通过APNs交换配对信息），每台设备生成256位AES密钥并存入钥匙串；BLE广播用AES-256-GCM加密并带重放保护，活动内容通过加密连接或APNs传输。大文件传输会从BLE切换到Apple点对点Wi-Fi，并用TLS与iCloud Keychain身份建立信任。

Universal Clipboard复用Handoff，把剪贴板内容同步到同一iCloud账户的其他设备。Apple明确指出，应用可以在用户未粘贴的情况下访问剪贴板，而Universal Clipboard把这种访问扩展到其他设备。这意味着：同一Apple Account下的受控Mac/iPad可能成为剪贴板数据的接收端；Handoff的活动元数据也可能泄露正在浏览的域名/文档。

| 能力 | 发现 | 传输 | 身份/加密 | 主要风险 |
|---|---|---|---|---|
| AirDrop | BLE短哈希 | AWDL + TLS | iCloud身份证书、联系人比对 | 恶意文件、身份枚举、骚扰 |
| Handoff | BLE 4.2 OOB配对 | BLE加密广播/APNs/AWDL | AES-256-GCM、iCloud Keychain | 活动元数据、同账户设备 |
| Universal Clipboard | Handoff | 加密通道 | 同账户信任 | 剪贴板泄露、跨设备复制 |
| Wi-Fi密码共享 | BLE广播 | BLE | 联系人/身份验证 | 密码被邻近设备诱导分享 |

### 4.3 攻击模型

AirDrop/Continuity的攻击更偏向“信任关系滥用”而非“协议漏洞”。攻击者若控制同一Apple Account的设备，或诱导用户接受恶意配件/文件，就能进入受信集合；之后的活动同步、剪贴板、文件传输都可能成为数据通道。企业应把“同一Apple Account的设备”视为一个信任域，审计受信设备、限制个人iCloud、使用托管Apple Account，并在高敏感场景关闭Handoff与Universal Clipboard。

检测上，`sharingd`与`rapportd`的统一日志、AirDrop接收事件、AWDL接口`awdl0`的流量、以及异常的文件打开链（AirDrop→Quick Look→Safari）都值得关注。由于AirDrop传输是本地TLS，网络侧只能看到AWDL的存在与流量特征，不能看到内容。

## 五、NFC与Apple Pay/Express模式

### 5.1 CoreNFC与标签攻击面

CoreNFC支持NDEF、ISO 7816、ISO 15693、FeliCa与MIFARE。`NFCTagReaderSession`的`PollingOption`可选择`.iso14443`、`.iso15693`、`.iso18092`；连接标签后通过`NFCISO7816Tag.sendCommand(apdu:completionHandler:)`发送APDU，`NFCISO7816APDU`包含`instructionClass`、`instructionCode`、`p1Parameter`、`p2Parameter`、`data`与`expectedResponseLength`。

攻击面包括：恶意NDEF写入URL/Universal Link，诱导Safari打开漏洞页面；仿冒标签类型触发应用解析缺陷；利用后台标签读取在用户不知情时弹出通知；通过标签锁定/容量耗尽做拒绝服务。iPhone XS/XR及以后支持后台NDEF读取，系统在屏幕点亮时读取标签并显示通知；用户仍需点击通知才会打开链接，因此这是一条“一交互”路径，而不是零点击。

企业可用`allowNFC=false`关闭NFC；个人应避免扫描来源不明的标签，关闭不需要的后台标签读取（入口随版本变化），并检查Wallet中的Express Mode卡片。

### 5.2 Secure Element与Apple Pay

Apple Pay的凭证存储在Secure Element的Java Card applet中，Secure Element通过EMVCo与Common Criteria认证；NFC控制器在应用处理器、Secure Element与POS终端之间路由。支付时，终端直接与Secure Element通信，NFC控制器只把“来自场端”的请求标记为contactless；卡号以Device Account Number（DPAN）形式存储，交易使用动态密码，真实PAN不落在设备或Apple服务器上。

授权由Secure Enclave管理：Face ID/Touch ID或设备密码通过后，SEP向Secure Element发送认证数据，applet才激活NFC接口。应用内/网页支付走应用处理器，但支付数据由Secure Element加密后发往Apple Pay服务器。这个设计使“应用处理器被攻陷”不等于“支付凭证可被读出”，但也不意味着支付链路没有攻击面：POS终端、收单行、商户风控、以及用户授权界面都可能被滥用。

### 5.3 Express Mode与EMV

Express Mode允许交通卡、门禁卡、车钥匙等在不解锁、不唤醒设备的情况下使用；部分机型在电量耗尽后仍可通过备用电量完成Express交易。它牺牲了“每次支付都要认证”的安全性，换取通行效率。对攻击者而言，Express Mode是“靠近即可触发”的高价值目标：恶意POS/读卡器可以发起交易，用户可能未察觉；交通/门禁场景的离线授权与事后扣费也增加了争议处理难度。

EMV contactless的典型流程是：SELECT PPSE（`2PAY.SYS.DDF01`）→ SELECT AID → GPO（`80 A8`）→ READ RECORD（`00 B2`）→ GENERATE AC（`80 AE`）。响应包含ATC、IAD与应用密文（cryptogram）。Apple Pay在此之上使用tokenization与动态密码，降低了“静态卡号被复制”的风险，但不能阻止中继、恶意终端或社会工程。

NFC中继/隔空刷卡是公开研究过的攻击类别：攻击者用两台设备把APDU在卡片与终端之间转发。Apple Pay的in-field判定、动态密码与风控提高了门槛，但能否完全阻断取决于具体实现与收单方风控；公开资料未披露Coruna/DarkSword涉及支付中继。企业应把“支付/门禁”与“普通数据”分开评估，个人应关闭不用的Express卡片。

### 5.4 NFC & SE平台与HCE

iOS 18.1起，Apple在监管开放地区提供NFC & SE平台，授权开发者可在Secure Element中存储支付、门禁、交通、票券与证件凭证；applet需通过第三方安全评估与Apple审核，运行在隔离的Security Domain中，只有关联的iOS应用可以访问。交易要求应用在前台、设备解锁，并通过Face ID/Touch ID/密码加物理手势授权；默认非接触应用可在双击侧边键后启动。

部分地区自iOS 17.4起开放HCE（Host Card Emulation），允许第三方应用在应用处理器上模拟卡片。HCE的信任模型与Secure Element不同：凭证/密钥在应用侧，安全性依赖应用实现、设备完整性与风控；这扩大了NFC支付生态的攻击面，但也受entitlement、地区与审核约束。企业应区分SE凭证与HCE凭证的风险，不要把“Apple Pay安全”直接套用到所有NFC应用。

## 六、UWB与空间感知

### 6.1 架构与API

UWB使用超宽带脉冲进行精细测距，iPhone的U1/U2芯片支持设备间/配件间的空间感知。`NISession`通过`NINearbyPeerConfiguration`或`NINearbyAccessoryConfiguration`启动，双方先交换`NIDiscoveryToken`，再通过`NISessionDelegate`接收`NINearbyObject`的距离/方向更新；`NIAlgorithmConvergence`表示测距算法的收敛状态。UWB还用于AirTag的精确查找、CarKey的无感进入与Find My生态。

Apple的UWB安全设计包括MAC地址随机化、Wi-Fi帧序列号随机化与Secure Ranging。IEEE 802.15.4z的增强测距在物理层加入加密时间戳/安全 ranging 机制，目标是抵抗中继与距离欺骗；具体实现与密钥管理未完全公开。

### 6.2 攻击模型

UWB的攻击面包括：物理层中继/放大、距离欺骗、 preamble 注入、拒绝服务与隐私关联。公开研究已展示对部分UWB测距系统的距离操纵；Apple的Secure Ranging设计目标就是提高这类攻击的成本，但不能假设所有UWB应用都等价安全。CarKey等高风险场景通常叠加NFC/SE认证、车主授权与车辆侧风控。

对Coruna/DarkSword而言，UWB不是一个合理的数据外传通道：它带宽极低、协议封闭、需要配对/令牌。它更可能是“空间触发”或“设备存在性”信号，但公开资料未披露这类行为。企业应把UWB视为定位与物理访问控制的一部分，而不是网络传输面。

## 七、Coruna/DarkSword中无线角色的推断分析

### 7.1 证据分级

| 能力 | Coruna | DarkSword | 证据强度 | 说明 |
|---|---|---|---|---|
| 通过NFC标签投递URL | 架构上可行 | 架构上可行 | 低 | 公开资料未披露具体投递 |
| 通过AirDrop投递文件 | 架构上可行 | 架构上可行 | 低 | 需用户接受与打开 |
| 通过Wi-Fi captive portal诱导 | 架构上可行 | 架构上可行 | 低 | 常见社工路径 |
| 原生载荷调用CoreBluetooth/CoreNFC | 可能 | 不适用 | 中/低 | 取决于载荷权限与TCC |
| JS直接调用无线框架 | 不适用 | 不可能 | 高 | WebContent沙箱限制 |
| BLE GATT低带宽外传 | 可能 | 不太可能 | 低 | 需原生桥接与配对 |
| AWDL/AirDrop外传 | 可能 | 不太可能 | 低 | 需原生能力与用户交互 |
| UWB触发/外传 | 不太可能 | 不太可能 | 低 | 带宽/协议限制 |

### 7.2 投递

从架构上看，Coruna/DarkSword都可能借助NFC标签、AirDrop文件、Wi-Fi captive portal把目标引到浏览器。NFC标签可以写入URL，系统读取后显示通知，用户点击进入Safari；AirDrop可以发送HTML/PDF/媒体文件，用户选择用Safari或Quick Look打开；captive portal可以在加入Wi-Fi时自动弹出登录页。这些路径共同点是“需要用户动作”，因此它们不能替代零点击WebKit链，只能作为前置。

公开资料没有披露两者使用上述任何一种无线投递。把它们写成“Coruna通过NFC传播”会制造虚假事实。更严谨的表述是：无线投递与两者的浏览器中心能力兼容，但证据不足，属于低置信度假设。

### 7.3 触发

NFC后台标签读取是iOS上少数“设备靠近即产生系统事件”的机制；AirDrop/Handoff也会在邻近设备上产生提示。对纯JS的DarkSword，触发只能发生在浏览器已经打开之后；它无法从WebContent中监听NFC/BLE事件。对Coruna，如果原生载荷已经驻留，理论上可以注册蓝牙/NFC相关服务或轮询状态，但这需要相应权限与后台模式，且会留下系统日志。

因此，无线触发对DarkSword的价值低于对Coruna；对两者都不如消息/浏览器入口重要。防御优先级也应如此。

### 7.4 外传

无线外传的带宽与可靠性都不如Wi-Fi/蜂窝：BLE GATT适合小数据，NFC只有几厘米且速率低，UWB不是数据通道，AWDL/AirDrop带宽较高但需要用户交互与近距离。Coruna的原生载荷若具备网络权限，完全可以用HTTPS/C2外传，无线只是备用；DarkSword的JS只能通过Web API外传，无法直接使用蓝牙/NFC。

```text
                  ┌─────────────────────┐
NFC标签 ─────────►│ Safari / WebContent │
AirDrop文件 ─────►│  （用户打开）        │
Wi-Fi portal ────►└─────────┬───────────┘
                            │ 漏洞链
                  ┌─────────▼───────────┐
                  │ 沙箱逃逸 / 内核能力  │
                  └───────┬─────┬───────┘
                          │     │
           ┌──────────────▼─┐ ┌─▼──────────────┐
           │ 原生载荷        │ │ 纯JS逻辑        │
           │ 可调用无线API   │ │ 仅Web通道       │
           └───────┬────────┘ └───────┬────────┘
                   │                  │
        ┌──────────▼─────────┐  ┌─────▼──────────┐
        │ BLE/AWDL/NFC 外传  │  │ HTTPS/WebSocket│
        │ （低置信度）        │  │ （主要路径）    │
        └────────────────────┘  └────────────────┘
```

## 八、无线链路风险矩阵

### 8.1 评分方法

沿用四因子思路，但把“可利用性”替换为“暴露度/可达性”E：`R = 4 × L × I × (E/5) × ((6-D)/5)`。L为可能性，I为影响，E为物理/协议可达性，D为检测覆盖（5为最好）。分级沿用P0–P4：P0≥70、P1 50–69、P2 30–49、P3 20–29、P4<20。评分是示例，不是统计概率。

### 8.2 场景评分

| ID | 场景 | L | I | E | D | R | 优先级 | 说明 |
|---|---|---|---|---|---|---|---|---|
| W1 | BLE广播跟踪/身份泄露 | 4 | 2 | 5 | 2 | 25.6 | P3 | 低影响、高可达 |
| W2 | 恶意BLE外设/GATT仿冒 | 3 | 3 | 4 | 3 | 17.3 | P4 | 需用户连接 |
| W3 | 恶意HID/ANCS配件 | 2 | 4 | 3 | 3 | 11.5 | P4 | 需配对授权 |
| W4 | AirDrop恶意文件 | 2 | 4 | 3 | 3 | 11.5 | P4 | 需接受/打开 |
| W5 | Handoff/剪贴板泄露 | 2 | 4 | 4 | 3 | 15.4 | P4 | 同账户信任 |
| W6 | NFC标签→浏览器 | 3 | 4 | 5 | 3 | 28.8 | P3 | 一交互 |
| W7 | NFC中继/盗刷 | 2 | 4 | 4 | 3 | 15.4 | P4 | 支付风控 |
| W8 | Express Mode恶意终端 | 3 | 3 | 5 | 3 | 21.6 | P3 | 免认证 |
| W9 | UWB中继/距离欺骗 | 1 | 5 | 4 | 4 | 6.4 | P4 | 需专业设备 |
| W10 | AWDL/AirDrop DoS | 3 | 2 | 4 | 2 | 15.4 | P4 | 可用性 |
| W11 | 恶意Wi-Fi portal | 4 | 4 | 3 | 3 | 23.0 | P3 | 社工 |
| W12 | NFC & SE/HCE应用风险 | 2 | 4 | 4 | 3 | 15.4 | P4 | 生态/地区 |

### 8.3 解读

无线场景的分数普遍低于浏览器/消息链，原因不是“无线不重要”，而是“高影响场景的可达性/可能性较低”。W1、W6、W8、W11接近P3门槛，说明隐私跟踪、NFC触发、免认证支付与Wi-Fi社工值得单独投入。对高价值目标，若L上调1，W6可进入P2，W8也会明显上升，应优先处理。

## 九、检测与加固

### 9.1 MDM与配置描述文件

| 控制项 | 键/配置 | 作用 | 备注 |
|---|---|---|---|
| 关闭AirDrop | `allowAirDrop=false` | 禁止AirDrop | 监督设备 |
| 限制蓝牙修改 | `allowBluetoothModification=false` | 防止用户改动蓝牙设置 | 可用性随版本 |
| 禁止主机配对 | `allowHostPairing=false` | 阻断非监督主机配对 | 监督设备 |
| 关闭NFC | `allowNFC=false` | 禁用NFC | 影响Apple Pay/门禁 |
| USB限制 | `allowUSBRestrictedMode=true` | 锁屏1小时后阻断USB数据 | 默认即true，勿设为false |
| Wi-Fi基线 | `com.apple.wifi.managed` | `SSID_STR`、`EncryptionType`、`EAPClientConfiguration`、`TrustedServerCertificates`、`AutoJoin` | 不要关闭MAC随机化 |
| 更新强制 | `com.apple.configuration.softwareupdate.enforcement.specific` | DDM设定目标版本/截止时间 | 监督设备 |
| 配置保护 | `PayloadRemovalDisallowed=true` | 防止删除管理描述文件 | 需谨慎，避免锁定 |

`allowUSBRestrictedMode`的语义容易误解：true表示保持USB Restricted Mode，false表示允许锁屏后继续使用USB配件。企业应确认该键没有被错误设为false。`allowNFC=false`会同时影响Apple Pay与门禁，需按角色分组，而不是全员一刀切。

Wi-Fi配置中应使用EAP-TLS、受信CA与`TrustedServerCertificates`，关闭不必要的`AutoJoin`；`DisableAssociationMACRandomization`如设为true会降低隐私，不建议作为默认。对高敏感场景，可用per-app VPN与DNS代理，但要注意网络扩展本身也是攻击面。

### 9.2 日志与遥测

iOS统一日志可按进程过滤：

```bash
log stream --predicate 'process == "bluetoothd" OR process == "sharingd" OR process == "rapportd" OR process == "nfcd"'
log show --last 24h --predicate 'process == "bluetoothd"' --style compact
```

在macOS侧，可用`rvictl -s <UDID>`创建`rvi0`并抓取iOS网络流量；蓝牙可用Apple的Bluetooth logging profile配合PacketLogger；Wi-Fi可用WIDS/WIPS或专用嗅探器；NFC没有公开的通用嗅探API，主要依赖`sysdiagnose`、`nfcd`日志、Wallet交易记录与终端侧日志。BLE可用nRF Sniffer、Ubertooth或专业分析仪做被动广播捕获，但加密连接内容仍需密钥。

`sysdiagnose`应纳入事件响应包：它包含系统日志、崩溃、网络、蓝牙/Wi-Fi状态与配置快照。企业可通过MDM收集诊断或要求用户手动触发；但不要把“日志已上传”当成“检测已覆盖”，因为日志保留期、符号化与关联规则才是关键。

### 9.3 加固清单

企业侧：对高敏感角色关闭AirDrop/NFC/主机配对；禁用不必要的蓝牙外设与后台模式；使用受管Wi-Fi与EAP-TLS；限制配置描述文件与根CA；启用Lockdown Mode（注意其与描述文件安装/MDM注册的交互）；强制更新；审计同一Apple Account的受信设备；对支付/门禁设备单独分组。

个人侧：AirDrop设为“仅联系人”或关闭；关闭“将设备靠近以共享”；不需要时关闭Handoff与Universal Clipboard；删除不用的蓝牙配对；不扫描陌生NFC标签；关闭不用的Express Mode卡片；检查“VPN与设备管理”和“证书信任设置”；保持系统更新；高风险人群评估Lockdown Mode。

需要强调：控制中心里的蓝牙图标只断开当前连接，不等同于在设置中关闭蓝牙；NFC没有面向所有机型的统一开关，企业应依赖MDM，个人应减少暴露行为而不是寻找“万能开关”。

## 十、结语

无线接口不是Coruna/DarkSword的主路径，但它提供了两条有价值的旁路：一条是把用户带到浏览器的“投递/触发”，另一条是原生载荷在无IP网络时的“低带宽外传”。对纯JavaScript的DarkSword，无线的作用被WebContent沙箱严格限制；对具备原生载荷的Coruna，无线能力取决于载荷权限、TCC与后台模式，不能仅凭“有内核权限”就推断其能随意使用蓝牙/NFC。

防御的重点不是猜测某条链是否使用无线，而是把无线当作独立的暴露面管理：减少可发现性、关闭不必要的免认证能力、审计配对与配置、建立近场与支付的检测基线。对高价值目标，NFC/Express Mode与AirDrop/Continuity应优先于普通蓝牙外设；对企业，MDM限制必须与角色分级结合，避免“一刀切”导致业务绕过。

最后，无线安全的最大风险往往不是某个协议漏洞，而是“默认开启+用户不理解+企业看不见”的组合。把这个组合拆开，分别用配置、流程与遥测去控制，才是可持续的无线攻击面收敛。

## 参考资料

- Apple Platform Security：Bluetooth security、AirDrop security、NFC & SE Platform security、Ultra Wideband security：https://support.apple.com/guide/security/welcome/web
- Apple：About Lockdown Mode：https://support.apple.com/en-us/105120
- Apple：Use Express Mode with transit cards, passes, and keys：https://support.apple.com/en-us/105123
- Apple Developer：Restrictions（MDM）：https://developer.apple.com/documentation/devicemanagement/restrictions
- Apple Developer：Core Bluetooth、Core NFC、Nearby Interaction 文档：https://developer.apple.com/documentation/
