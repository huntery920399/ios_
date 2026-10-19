# iOS设备管理与配置描述文件攻击面：从MDM到声明式设备管理的滥用与防护

## 摘要

配置描述文件（Configuration Profile）是 iOS 上少数能够在**不依赖代码签名、不触发内核漏洞**的前提下改变系统安全策略的官方机制。它以属性列表（plist）为载体，把根证书、Wi-Fi、VPN、代理、Web Clip、限制策略乃至 MDM 注册信息打包为一个可以被用户"点一下"就生效的对象。对攻击者而言，这是一条被系统主动信任的合法通道；对企业防御者而言，这是一个经常游离于资产清单之外的持久化面。

本文以系统安全视角拆解三层结构：描述文件与载荷类型、MDM 注册与监督模式、声明式设备管理（Declarative Device Management，DDM）。在此基础上讨论四类滥用路径——恶意 MDM、根证书与 TLS 拦截、Web Clip 社会工程、限制策略绕过——并给出与 Coruna、DarkSword 这类高级攻击链关系的**推断性**分析，明确标注推断边界。最后提供可执行的检测与加固清单，包括 ProfileList 对账、统一日志谓词、证书审计与监督模式下的限制键配置。

需要先划定事实边界：公开分析将 Coruna 描述为以 WebKit 远程入口加分阶段载荷为特征的攻击链，将 DarkSword 描述为以纯 JavaScript 多漏洞协同、较少依赖传统 Native Payload 为特征的攻击链。**公开资料未披露两者使用配置描述文件作为入口或持久化手段**。本文第四节之后涉及二者的内容均为攻击面推演，不构成事件归因。

## 关键词

配置描述文件；MDM；声明式设备管理；监督模式；根证书；TLS 拦截；Web Clip；攻击面管理

## 引言

移动设备管理（Mobile Device Management，MDM）在企业中的典型叙事是"合规"：强制密码、强制加密、推送 Wi-Fi、下发应用。但从安全研究的角度看，MDM 是 iOS 上权限最集中的**合法后门**：一个被正确注册的设备会自愿向远端服务器上报序列号、系统版本、已安装应用、证书列表，并接受安装描述文件、安装应用、锁定、擦除、查询位置等指令。这套能力的设计目的是资产管理，其能力集合与攻击者的目标集合高度重叠。

真正的问题不在于 MDM 协议本身是否安全——它使用 TLS、设备身份证书与 APNs 唤醒，设计上并不弱——而在于**信任的建立过程发生在用户侧**。用户被要求判断一个来源不明的"描述文件"是否可信，而这个判断所需要的技术信息（签名者、载荷类型、是否包含根证书）在安装界面上往往被折叠或弱化。攻击者不需要攻破 iOS，只需要说服用户点"允许"，就能获得一部分原本需要漏洞才能获得的效果。

本文不重复"不要安装未知描述文件"这类正确但无用的建议，而是回答三个工程问题：第一，描述文件与 MDM 在系统内部究竟能做什么，能力边界在哪里；第二，攻击者会优先滥用哪些载荷，为什么；第三，企业如何用**可验证的数据**而非用户自觉来发现异常。

## 一、配置描述文件与MDM架构

### 1.1 描述文件的本质是受信任的配置注入

一个 `.mobileconfig` 文件就是一份 plist，顶层键定义了这份配置的身份与安装行为：

```xml
<key>PayloadType</key>        <string>Configuration</string>
<key>PayloadIdentifier</key>  <string>com.example.profile</string>
<key>PayloadUUID</key>        <string>...</string>
<key>PayloadVersion</key>     <integer>1</integer>
<key>PayloadOrganization</key><string>Example Org</string>
<key>PayloadDisplayName</key> <string>Corporate Settings</string>
<key>PayloadRemovalDisallowed</key><true/>
<key>PayloadScope</key>       <string>System</string>
<key>PayloadContent</key>     <array> ... 若干子载荷 ... </array>
```

三个字段决定了它的安全属性：`PayloadIdentifier` 是去重与更新的主键，攻击者若覆盖同名标识符即可"替换"既有配置；`PayloadRemovalDisallowed` 为真时用户无法在设置中删除该描述文件，只能抹除设备或由 MDM 移除；`PayloadScope` 决定作用于系统域还是用户域。描述文件可以选择用 CMS（PKCS#7）签名，也可以加密，但**签名只证明"谁签的"，不证明"内容安全"**——一份由任意自签证书签署的描述文件同样可以安装，系统只会给出"未签名/未验证"的弱提示。

### 1.2 载荷类型即能力清单

描述文件的威力来自子载荷。下表按滥用价值排序，列出企业环境中最需要关注的类型。

| PayloadType | 主要字段 | 能力 | 滥用价值 |
| --- | --- | --- | --- |
| `com.apple.security.root` | `PayloadCertificateFileName`、`PayloadContent`（DER） | 安装根证书并**自动信任** | 极高：为 TLS 拦截提供信任锚 |
| `com.apple.mdm` | `ServerURL`、`CheckInURL`、`Topic`、`IdentityCertificateUUID`、`AccessRights`、`SignMessage` | 将设备注册到远端管理 | 极高：获得持续指令通道 |
| `com.apple.webClip.managed` | `URL`、`Label`、`Icon`、`IsRemovable`、`FullScreen` | 在主屏创建不可删除的网页入口 | 高：钓鱼与持久化入口 |
| `com.apple.dnsSettings.managed` | `DNSProtocol`、`ServerAddresses`、`SupplementalMatchDomains` | 指定 DNS 解析器 | 高：流量重定向与可见性 |
| `com.apple.vpn.managed` | `VPNType`、`RemoteAddress`、`OnDemandEnabled`、`OnDemandRules` | 建立 VPN / Always On 隧道 | 高：全流量接管 |
| `com.apple.proxy.http.global` | `ProxyType`、`ProxyServer`、`ProxyPACURL` | 全局 HTTP 代理 | 高：明文与元数据收割 |
| `com.apple.webcontent-filter` | `FilterType`、`PluginBundleID`、`FilterSockets` | 内容过滤（插件型为 Network Extension） | 高：可解密被放行流量 |
| `com.apple.applicationaccess` | 大量 `allow*` 布尔键 | 限制设备功能 | 中高：削弱取证与用户自救 |
| `com.apple.security.scep` | `URL`、`Name`、`Challenge`、`KeyUsage` | 自动申请设备身份证书 | 中：为 MDM 提供身份 |
| `com.apple.mobiledevice.passwordpolicy` | `minLength`、`maxFailedAttempts`、`maxInactivity` | 密码策略 | 中：可被用于制造锁定 |
| `com.apple.shareddeviceconfiguration` | 共享设备与临时会话参数 | 共享 iPad 场景 | 低到中：依赖场景 |

值得注意的是 `com.apple.security.root` 的信任语义：**通过 MDM 下发的根证书会被系统直接标记为信任，无需用户在"证书信任设置"中手动开启开关**。手工安装的根证书则需要用户额外进入"设置 > 通用 > 关于本机 > 证书信任设置"打开完全信任。这一差异意味着：一旦设备处于 MDM 管理之下，攻击者获得 CA 信任的成本几乎为零。

### 1.3 MDM 协议面：两条通道与一个唤醒

MDM 不是长连接，而是"推送唤醒 + 设备回连"的三段式结构。设备在注册时向 `CheckInURL` 提交身份，之后通过 APNs 收到唤醒，再向 `ServerURL` 拉取指令。

```text
+----------------+        HTTPS 443 (mTLS)        +----------------------+
|   iOS Device   |<------------------------------>|     MDM Server       |
|                |   PUT /checkin  (注册/令牌)     |  /mdm/checkin        |
|  MDM client    |   PUT /command  (轮询指令)      |  /mdm/command        |
|  + profiled    |   PUT /declarative (DDM)       |  /mdm/declarative    |
+-------+--------+                                 +----------+-----------+
        |                                                     |
        |  APNs 静默推送（仅唤醒，不含指令）                     | SCEP / EST
        v                                                     v
+----------------+      topic: com.apple.mgmt.External.<UUID>  +----------+
|  Apple APNs    |<-------------------------------------------+| 企业 CA  |
+----------------+        推送证书按租户绑定 Topic              +----------+
```

三段式的关键点在于：**APNs 只负责唤醒，真正的指令走 HTTPS 双向认证**。这既是安全设计，也是检测机会——推送本身不携带 payload，因此仅靠推送日志无法判断指令内容，必须结合 MDM 服务端审计与设备侧日志。

注册阶段的 check-in 消息体大致如下（字段随系统版本略有差异）：

```xml
<dict>
  <key>MessageType</key>   <string>Authenticate</string>
  <key>Topic</key>         <string>com.apple.mgmt.External.XXXXXXXX</string>
  <key>UDID</key>          <string>...</string>
  <key>OSVersion</key>     <string>17.5</string>
  <key>Model</key>         <string>iPhone15,2</string>
  <key>ProductName</key>   <string>iPhone14,2</string>
</dict>
```

随后设备发送 `TokenUpdate`，携带 APNs 令牌与（可选的）解锁令牌；解除注册时发送 `CheckOut`。指令通道则是服务端 PUT 一份 plist，设备以 `Status` 字段回复。五个状态值覆盖了绝大多数运维场景：`Acknowledged` 表示执行成功；`Error` 表示失败并附带 `ErrorChain`，需要按错误码分类；`CommandFormatError` 通常意味着版本不兼容；`Idle` 表示设备当前无法执行（锁屏或忙碌）；`NotNow` 表示设备拒绝立即执行，常见于用户主动拒绝或策略限制。排障时应优先区分 `Error` 与 `NotNow`，前者是协议或权限问题，后者往往是策略与用户行为问题。

`AccessRights` 是一个整数位掩码，直接决定这条通道的破坏半径。企业常见的问题是"为了方便排障，直接给 255"。各比特的含义与风险如下：

- **1**：查询已安装描述文件。风险低，但会泄露防御布局。
- **2**：安装与移除描述文件。风险高，可变更信任锚。
- **4**：锁定设备与清除密码。风险高，可造成拒绝服务。
- **8**：抹除设备。风险极高，等同于数据销毁。
- **16**：查询设备信息（序列号、容量）。风险中，可用于资产测绘。
- **32**：查询网络信息（号码、ICCID）。风险中，涉及敏感标识。
- **64**：查询已安装应用清单。风险中，暴露工具链与业务属性。

在协议层之上，MDM 还提供了一组"命令即能力"的原语：`DeviceInformation`（可查询 `IsSupervised`、`IsActivationLockEnabled`、`PasscodePresent` 等）、`SecurityInfo`、`CertificateList`、`ProfileList`、`InstalledApplicationList`、`Restrictions`、`InstallProfile`、`RemoveProfile`、`InstallApplication`、`DeviceLock`、`ClearPasscode`、`EraseDevice`、`EnableLostMode`、`DeviceLocation`、`ScheduleOSUpdate`。对企业这是运维工具，对攻击者这是**一份现成的目标能力清单**。

## 二、注册流程与监督模式

### 2.1 三种注册路径的信任差异

iOS 的注册路径可以粗分为用户注册（User Enrollment，面向 BYOD）、设备注册（Device Enrollment，面向企业资产）与自动设备注册（Automated Device Enrollment，ADE，配合 Apple Business Manager）。三者的核心差异不是技术协议，而是**谁掌握监督位**。

- 用户注册：使用托管 Apple ID，数据隔离在独立 APFS 卷，MDM 只能管理托管应用与托管账户，无法查询整机应用清单，也无法安装根证书到系统信任域。这是隐私边界最强、攻击价值最低的形态。
- 设备注册：整机纳管，可查询设备信息、安装描述文件、下发限制。若设备未被监督，用户仍可在设置中移除描述文件（除非 `PayloadRemovalDisallowed`）。
- ADE：设备在激活阶段即从 Apple 侧获取注册描述文件，监督位被置为真，用户无法跳过，描述文件默认不可移除。

### 2.2 监督模式是能力的分水岭

监督（Supervision）不是描述文件里的一个字段，而是设备激活时写入的一项持久状态，只能通过 ADE 或 Apple Configurator 建立，且**建立时通常需要抹除设备**。它带来的能力跃迁包括：静默安装与移除应用、静默安装描述文件、强制限制策略、禁用"信任此电脑"、启用单应用模式、限制 USB 配件、查询更多设备信息。对攻击者而言，监督设备是"高价值但难获得"的目标；对企业而言，监督是"能否真正落实限制策略"的前提。

```text
Apple Business Manager / ADE
        |
        | 采购记录与 MDM 服务器分配
        v
[设备激活] --> deviceenrollment.apple.com 获取 configuration_url
        |
        v
Setup Assistant 阶段下载并安装注册描述文件
        |
        +--> 写入监督位（Supervised = true）
        +--> 安装组织根证书（可自动信任）
        +--> 可选：静默安装 App、限制策略、Wallpaper
        |
        v
设备进入 MDM 指令循环（ProfileList / SecurityInfo / ...）
```

### 2.3 注册过程中的薄弱点

三个环节在真实环境中反复出问题。第一是**注册链接与二维码**：ADE 之外的注册通常通过 URL、二维码或邮件附件分发 `.mobileconfig`，攻击者可以复制同样的分发形式，把 `ServerURL` 指向自己的服务器。第二是**SCEP 挑战口令**：`com.apple.security.scep` 的 `Challenge` 常被硬编码在描述文件里，一旦泄露，攻击者可以为自己的设备申请合法身份证书。第三是**推送证书生命周期**：MDM 的 APNs 证书按租户绑定 Topic，若供应商的证书私钥或服务账号失守，攻击者可在不接触设备的情况下向租户内设备发送唤醒——虽然仍需设备回连到合法 MDM 才能下发指令，但这已足以构成拒绝服务或探测。

## 三、Declarative Device Management

### 3.1 从"命令式"到"声明式"

传统 MDM 是命令式的：服务端下发 `InstallProfile`，设备执行并回 `Acknowledged`。这种模式的问题是状态在服务端，设备只负责执行，双方很容易漂移。DDM（iOS 16 / macOS 13 起）把模型反过来：服务端下发**声明**（declaration），设备持续上报**状态**（status），由设备自己保证"声明所描述的状态"成立。

DDM 的声明是 JSON，由 `Type` 与 `Identifier` 唯一确定，`ServerToken` 用于变更检测。常见类型包括 `com.apple.activation.simple`（激活，引用一组配置）、`com.apple.configuration.management.organization-info`、`com.apple.configuration.management.status-subscriptions`（状态订阅）、`com.apple.configuration.passcode.settings`、`com.apple.configuration.softwareupdate.enforcement.specific`（强制更新截止时间）、`com.apple.configuration.legacy`（把传统载荷包装进声明式通道）以及 `com.apple.asset.*` 系列资产声明。

```text
MDM CheckIn: DeclarativeManagement
   Endpoint = "declaration-items"
        |
        v
设备收到:
{ "Declarations": { "Activations":[...], "Configurations":[...],
                    "Assets":[...], "Management":[...] },
  "DeclarationsToken": "..." }
        |
        +--> 拉取 activation/<id>：StandardConfigurations = [cfg-A, cfg-B]
        +--> 拉取 configuration/<id>：Payload（JSON，含具体设置）
        +--> 按 status-subscriptions 上报 StatusItems
        |
        v
状态回报示例（节选）:
{ "StatusItems": {
    "device.operating-system.version": { "value": "17.5" },
    "passcode.is-present":             { "value": true },
    "security.certificate.list":       { "value": [ ... ] } } }
```

### 3.2 状态通道的安全含义

DDM 最值得安全团队关注的不是"下发更快"，而是**状态通道变成了持续性的资产与合规遥测**。通过 `status-subscriptions`，MDM 可以订阅 `device.identifier.serial-number`、`device.operating-system.build-version`、`passcode.is-present`、`security.certificate.list` 等状态项，并在状态变化时收到上报。对防御方，这是检测漂移的最佳数据源：新增的根证书、版本回退、密码策略失效都会立刻反映在状态项里。对攻击者，一旦掌握这条通道，等同于获得一台"随时可查询、随时可下发"的资产探针，且查询行为在设备侧留下的痕迹比传统命令更少——**DDM 的静默性对攻防双方是对称的**。

另一个容易被忽略的点是 `com.apple.configuration.legacy`：它允许把传统描述文件载荷嵌入声明式通道。这意味着传统载荷的滥用面并没有因为 DDM 的引入而消失，只是换了一个投递容器。检测方案必须同时覆盖两代机制，不能假设"上了 DDM 就没有 mobileconfig 了"。

### 3.3 新能力带来的新风险

iOS 17 引入的 Return to Service 允许设备在不重新注册 MDM 的情况下抹除并回到服务状态，DDM 的软件更新强制可以设定安装截止时间。这些能力在企业场景非常实用，但也意味着**一条被攻陷的管理通道可以更快地把设备恢复到一个"攻击者可控的干净状态"**，从而清除本地痕迹。取证人员在遇到"设备刚被重置但仍处于托管状态"的情形时，应把管理侧的操作日志纳入时间线，而不是只依赖设备本地数据。

## 四、滥用路径

### 4.1 恶意 MDM：把管理通道变成控制通道

最直接的路径是让设备注册到攻击者控制的 MDM。实现方式有三类：伪造注册页面诱导用户安装含 `com.apple.mdm` 载荷的描述文件；攻陷企业现有 MDM 服务器或其供应链（MDM 产品本身是高风险目标，历史上出现过网关组件被远程利用的公开案例）；滥用 ADE 分配，把设备错误地指派到攻击者租户。第一条依赖社会工程，第二条依赖漏洞或凭据，第三条依赖管理流程缺陷。

一旦注册成功，攻击者获得的能力与合法管理员完全一致，区别只在于指令内容：查询应用清单以寻找高价值目标、下发根证书以开启拦截、安装 Web Clip 做钓鱼入口、`DeviceLocation` 定位、`EraseDevice` 销毁证据。**这类攻击不需要任何 iOS 漏洞，也不会触发代码签名校验**，因此传统以"是否越狱/是否植入恶意二进制"为核心的检测思路会完全失效。

从攻击成本看，恶意 MDM 路径有一个反直觉的特点：它的**初始成本高于漏洞利用，但边际成本极低**。一次成功的钓鱼注册可以覆盖同组织内大量设备，且后续新增指令不需要重新获得用户授权。这也是为什么在成熟的黑产与商业间谍软件生态中，"管理面"往往由专门的访问代理（access broker）负责，而不是由漏洞研究者兼任——两者需要的能力模型完全不同。

### 4.2 根证书与 TLS 拦截

根证书是整条滥用链上性价比最高的一环。安装 `com.apple.security.root` 后，攻击者配合 `com.apple.proxy.http.global`、`com.apple.vpn.managed`、`com.apple.dnsSettings.managed` 或插件型 `com.apple.webcontent-filter`，即可把设备的 HTTP(S) 流量导向自己的代理。对使用证书固定（certificate pinning）的应用无效，但对大量未做固定的企业内网应用、Web 视图、更新检查请求有效。

需要澄清一个常见误解：**安装根证书不等于能解密所有流量**。TLS 1.3、证书固定、双向认证、QUIC/HTTP3 都会提高拦截成本；iOS 上部分系统服务使用独立信任评估，不读取用户安装的根证书。攻击者的现实收益是" selective 拦截"——针对未做固定的目标应用与浏览器流量，而不是全量解密。

### 4.3 Web Clip：最被低估的持久化入口

`com.apple.webClip.managed` 会在主屏生成一个图标，点击后以独立 Web 视图打开指定 URL。它的滥用价值体现在三点：图标可以伪装成企业应用或系统设置；`IsRemovable=false` 时用户无法删除；`FullScreen=true` 时可隐藏地址栏，使钓鱼页面看起来像原生界面。更进一步，配合 `IgnoreManifestScope` 与精心构造的 manifest，页面可以获得接近独立 Web App 的行为。对于以"窃取凭据"为目标的攻击者，一个不可删除的、指向攻击者站点的图标，其投入产出比远高于寻找浏览器漏洞。

### 4.4 限制策略的双刃剑

`com.apple.applicationaccess` 中的 `allow*` 键本意是合规，但其中若干项会直接削弱用户的自我保护和取证能力：

| 限制键 | 设为 false/true 的效果 | 滥用后果 |
| --- | --- | --- |
| `allowHostPairing` = false | 禁止与电脑配对 | 阻断传统取证与备份 |
| `allowUSBRestrictedMode` = true | 限制 USB 配件 | 增加物理提取难度 |
| `allowEnterpriseAppTrust` = true | 允许信任企业开发者 | 为侧载打开口子 |
| `allowUntrustedTLSPrompt` = false | 不提示不可信证书 | 降低拦截被发现概率 |
| `allowUIConfigurationProfileInstallation` = false | 禁止用户从界面安装描述文件 | 反向用于"锁死"已有配置 |
| `allowScreenShot` = false | 禁止截屏 | 影响用户留存证据 |
| `allowRemoteScreenObservation` = true | 允许远程屏幕观察 | 屏幕内容可被持续获取 |

`allowEnterpriseAppTrust` 与 `allowUntrustedTLSPrompt` 的组合尤其危险：前者允许安装企业签名应用，后者压制证书警告，两者叠加可以把设备变成一个"对中间人几乎无感"的终端。

### 4.5 擦除、锁机与拒付

MDM 的 `EraseDevice`、`DeviceLock`、`ClearPasscode` 在事件响应中常被用于"止损"，但在攻击场景中它们是**证据销毁工具**。攻击者只需一次 `EraseDevice`，设备本地日志、应用数据、描述文件痕迹全部消失；而 `EnableLostMode` 可以被用来制造"设备丢失"的假象，掩盖远程控制行为。企业在设计管理权限时，必须把这几个命令列入"双人审批"清单，而不是给一线运维默认权限。

## 五、与商业间谍软件生态的关系推断

以下内容为攻击面推演，**公开资料未披露 Coruna 或 DarkSword 使用描述文件机制**，不应作为事件结论引用。

Coruna 的公开特征是以 WebKit 为远程入口、分阶段投递载荷，这意味着其初始突破发生在渲染进程，随后需要沙箱逃逸与提权。描述文件在这条链上没有位置——它既不能帮助突破 WebKit，也不能替代内核提权。真正值得推演的是**后利用阶段**：攻击者获得 root 后，如果要长期维持访问、扩大可见性、或在设备被复查时提供"合理解释"，描述文件是一个低痕迹选项。例如，安装一个自签 CA 加全局代理，可以让后续 C2 流量混入正常 TLS；安装一个伪装成"企业配置"的 Web Clip，可以在主载荷被清除后保留回访入口。这些操作的共同点是**不依赖代码执行持久化**，因而在只检查二进制与启动项的传统查杀中不可见。

DarkSword 的公开特征是纯 JavaScript 多漏洞协同、较少依赖 Native Payload。这一特征反而降低了其使用描述文件的动机：纯脚本链的核心优势是"无文件、少落盘"，而描述文件必然留下可枚举的持久化对象（`ProfileList` 一条记录、`/private/var/db/ConfigurationProfiles` 下的存储、安装日志）。**对追求隐蔽的攻击者，描述文件是"高可见度的持久化"**，通常只在需要跨越重启、需要系统级信任锚、或需要管理能力时才值得付出这个代价。

由此可以给出一个防御推论：如果一起事件中发现了异常描述文件，它更可能是**独立的社会工程攻击或内部人员行为**，而不是 WebKit 漏洞链的标配组件；反之，如果确认存在 Coruna/DarkSword 类内存攻击，不应因为"没看到描述文件"就排除持久化，也不应把描述文件当作攻击链的必需环节。二者是**并行的攻击面**，而非同一链条的固定阶段。

## 六、检测

### 6.1 设备侧：以 ProfileList 为基线做对账

MDM 自带的 `ProfileList` 是最可靠的全量清单来源，返回字段包括 `ProfileIdentifier`、`ProfileUUID`、`ProfileDisplayName`、`ProfileVersion`、`ProfileInstallDate`、`ProfileOrganization`、`ProfileIsRemovable`、`ProfileIsManaged` 以及每个载荷的 `PayloadType`、`PayloadIdentifier`、`PayloadVersion`、`PayloadDescription`。

工程上应做三件事。第一，把 `ProfileList` 的结果按设备序列号入库，形成"应有基线"，任何新增、变更、`ProfileIsRemovable=false` 的条目都触发告警。第二，对 `ProfileOrganization` 与签名者做白名单校验——注意该字段由描述文件自称，**不可作为信任依据**，必须结合 CMS 签名证书指纹。第三，定期比对 `CertificateList` 与 `security.certificate.list` 状态项，任何非企业 CA 的根证书都应视为高危。

### 6.2 日志：统一日志中的管理面痕迹

设备侧的统一日志（Unified Logging）会记录描述文件安装、MDM 注册与声明式同步。在拿到 sysdiagnose 后，可在 macOS 上离线检索：

```bash
# 解包 sysdiagnose
tar -xzf sysdiagnose_*.tar.gz

# 管理面日志（描述文件安装、MDM 注册）
log show --archive ./system_logs.logarchive \
  --predicate 'subsystem == "com.apple.ManagedConfiguration"' \
  --info --debug --last 7d

# 声明式管理相关
log show --archive ./system_logs.logarchive \
  --predicate 'eventMessage CONTAINS[c] "declaration" OR eventMessage CONTAINS[c] "DeclarativeManagement"' \
  --info --debug

# 进程维度：profiled / mdm 客户端
log show --archive ./system_logs.logarchive \
  --predicate 'process == "profiled" OR process CONTAINS[c] "mdm"'
```

需要注意三点局限：统一日志在设备上的留存窗口很短（通常数天，取决于写入量），**攻击者只要等待即可让日志自然过期**；大量字段默认私有化（`<private>`），除非安装了开启私有数据记录的描述文件，否则看不到具体标识符；日志时间戳依赖 timesync 文件，若该文件被删除，时间线会出现空洞或偏移。

### 6.3 证书审计：从"有没有装"到"装了做什么"

证书审计不能只看数量。建议对每张非预期根证书计算 SHA-256 指纹，并核对：主体与签发者是否一致（自签）、有效期是否异常（超长或即将过期）、密钥用途是否包含 `TLS Web Server Authentication`、是否带 `nameConstraints`。在 macOS 上可对导出的证书做离线检查：

```bash
openssl x509 -in ca.cer -inform DER -noout -subject -issuer -dates \
  -fingerprint -sha256 -ext basicConstraints,keyUsage
```

对仍在使用旧版配置的设备，还应检查 `com.apple.security.root` 是否与 `com.apple.proxy.http.global`、`com.apple.vpn.managed`、`com.apple.dnsSettings.managed` 出现在**同一份描述文件**中。这种组合几乎只有一个合理解释：流量拦截。合法的企业 TLS 检查通常由独立的、受控的描述文件承担，并与代理配置分离。

### 6.4 服务端与网络侧

MDM 服务端应记录每一条指令的 `CommandUUID`、操作者、目标设备、时间与结果，并保留至少 180 天。检测规则可以很朴素但有效：非工作时间的批量 `InstallProfile`、对非托管设备发起的 `ProfileList`、`AccessRights` 被提升、同一操作者在短时间内对大量设备执行 `EraseDevice`。

网络侧关注三类信号：设备向陌生 `ServerURL` 发起的 mTLS 回连（可通过出口 TLS 元数据与 SNI 观察）；内网出现非企业 SCEP 端点；设备在非工作时间出现规律性短连接。这些信号单独看都很弱，但与 MDM 侧日志关联后，足以还原"谁在什么时候把哪台设备纳管到了哪里"。

### 6.5 一条可落地的审计流水线

把上述数据源串起来，可以得到一条不依赖高级分析平台的流水线。它的设计目标是"每天用可重复的方式回答三个问题"：设备上有什么配置、这些配置是谁装的、装完之后发生了什么。

```text
[每日 02:00 定时任务]
      |
      +--> 1. MDM API: ProfileList / CertificateList / InstalledApplicationList
      |         |
      |         v
      |    规范化: device_id, profile_id, payload_types[], cert_sha256[]
      |
      +--> 2. 与基线库比对（允许清单 + 历史快照）
      |         |
      |         +--> 新增 profile --------> 告警（高）
      |         +--> 新增根证书 ----------> 告警（高）
      |         +--> RemovalDisallowed 变化 -> 告警（中）
      |         +--> 代理/VPN 与根证书同现 --> 告警（高）
      |
      +--> 3. 关联身份与网络日志
                |
                +--> 同一操作者批量操作？ -> 升级
                +--> 设备回连陌生 ServerURL？ -> 升级
                +--> 非工作时段 EraseDevice？ -> 升级
```

流水线的关键不在告警规则，而在**基线库的维护成本**。如果每次业务变更都要手工改允许清单，规则很快会被"临时放行"侵蚀。可行的做法是把基线定义为"由变更管理系统签发的描述文件标识符集合"，让 MDM 只接受带工单号的配置，从而使基线自动跟随变更，而不是跟随运维人员的记忆。

规则本身可以写得很朴素。例如下面这条伪 Sigma 规则，用于发现"设备上出现了包含根证书与全局代理的组合配置"：

```yaml
title: iOS Profile Bundles Root CA with Global Proxy
logsource:
  product: mdm
  category: profile_inventory
detection:
  root_ca:
    payload_types|contains: 'com.apple.security.root'
  proxy:
    payload_types|contains:
      - 'com.apple.proxy.http.global'
      - 'com.apple.vpn.managed'
      - 'com.apple.dnsSettings.managed'
  filter_known:
    profile_identifier|startswith: 'com.example.approved.'
  condition: root_ca and proxy and not filter_known
level: high
```

这类规则的价值在于它描述的是**能力组合**而不是具体样本：即使攻击者更换了描述文件名称、UUID 或服务器域名，只要"根证书 + 流量重定向"的组合成立，就会被命中。同理，`ProfileIsRemovable=false` 且 `ProfileOrganization` 与资产库不一致、`AccessRights` 位掩码包含 8 且操作者不在 break-glass 名单，都是稳定的行为特征。

## 七、加固

### 7.1 把"能否安装描述文件"变成策略问题

对受监督设备，最有效的单项措施是关闭用户界面安装描述文件的入口：`allowUIConfigurationProfileInstallation=false`（iOS 16 及以上）。这条限制的语义是"用户不能从设置或文件手动安装配置描述文件"，它不阻止 MDM 下发，因此不会影响正常运维，却能直接切断"钓鱼诱导安装"的主路径。配套的限制建议如下：

- `allowHostPairing=false`：阻断与未知电脑配对，降低物理取证与备份窃取风险。
- `allowUSBRestrictedMode=true`：限制 USB 配件，提高物理接触攻击成本。
- `allowEnterpriseAppTrust=false`：禁止信任企业开发者证书，除非确有内部分发需求。
- `allowUntrustedTLSPrompt=true`：保留证书警告，不要为了"减少打扰"而关闭。
- `allowVPNCreation=false`：禁止用户自建 VPN 配置，避免隧道被用于绕过出口管控。
- `allowRemoteScreenObservation=false`、`allowScreenShot=true`：保留用户留存证据的能力。
- `forceITunesStorePasswordEntry=true`：购买或更新时强制输入密码，降低账号劫持后的静默安装风险。

这些键大多只在监督模式下生效，这也是为什么"监督"应当被视为企业移动安全的基线，而不是可选项。

### 7.2 证书与信任锚治理

企业应维护一份"允许出现在托管设备上的根证书清单"，清单之外一律告警。根证书只能由受控的私有 CA 签发，且应设置较短有效期与明确的 `nameConstraints`；不要使用来源不明的公共 CA 证书做内网拦截。对 MDM 端点本身启用证书固定，避免管理通道被中间人劫持后下发恶意指令。对外部暴露的 MDM 服务，应强制 mTLS、限制来源 IP、把管理面与设备面分离，并对供应商漏洞保持常态化的补丁节奏——MDM 服务器是"一旦失守即全军覆没"的资产，其安全等级应高于普通业务系统。

### 7.3 权限最小化与流程约束

`AccessRights` 应按角色拆分：一线服务台只给查询类权限（16、32、64），描述文件变更与擦除类权限（2、4、8）必须走双人审批与工单留痕。ADE 的设备分配应有独立的审批流，防止"把设备指派到错误租户"这类低成本高影响的事故。对 DDM，应订阅 `security.certificate.list`、`passcode.is-present`、`device.operating-system.version` 等状态项，把"配置漂移"变成可持续监控的指标，而不是季度审计时才发现的问题。

### 7.4 面向高级攻击的补充措施

对高风险人群（高管、财务、研发核心），仅靠 MDM 不足以应对 Coruna/DarkSword 这类攻击链。可叠加的措施包括：开启锁定模式（Lockdown Mode）以削减 WebKit 与消息面的攻击面；保持系统在最新小版本，优先启用快速安全响应；对高价值账户启用硬件安全密钥；把"设备是否被托管""是否安装非预期根证书""是否出现异常网络回连"纳入同一套风险评分模型。需要明确的是，这些措施降低的是概率与驻留时间，而不是提供绝对防护。

## 八、结语

配置描述文件与 MDM 的风险，本质上不是密码学问题，而是**信任边界问题**：系统把"改变安全策略"的能力交给了一份可以被邮件附件传递的 plist，并把最终判断交给了用户。监督模式与 DDM 提升了企业的控制力，但同一套能力在攻击者手中同样有效，而且不需要任何内存破坏漏洞。

对防御者，可操作的结论只有三条：第一，用监督模式把"用户能否安装描述文件"变成确定性策略；第二，用 ProfileList、CertificateList 与 DDM 状态项建立可对账的基线，让异常配置无处藏身；第三，把 MDM 服务器当作最高价值资产来防守，因为它一旦失守，设备侧的所有加固都会在一条指令内被改写。至于 Coruna 与 DarkSword，它们提醒我们：高级攻击链与合法管理通道是两条并行路径，防御不能只盯着其中一条。
