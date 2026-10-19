# iOS应用数据容器与AppGroup安全-从共享文件到跨应用横向移动的攻防分析

## 摘要

iOS 的沙箱常被概括为“每个 App 一个盒子”。这个比喻方向正确，却掩盖了盒子内部的复杂结构：Bundle 容器与 Data 容器分离，Documents、Library、tmp 具有不同的备份与清理语义，Data Protection 按文件粒度决定锁屏后的可读性，App Group 又把多个 App 与扩展放进同一个共享目录。对企业而言，真正危险的不是“App 能不能读自己的文件”，而是“一个被攻破的组件能沿着共享容器走多远”。

2024 至 2026 年的公开分析中，Coruna 与 DarkSword 代表了两种不同的落地方式：前者以 WebKit 入口加分阶段载荷为特征，后者以纯 JavaScript 多漏洞协同、较少依赖 Native Payload 为特征。两者都很少被公开披露具体的容器访问路径，但它们的数据收集阶段必然受容器、entitlement 与沙箱约束。本文以这些约束为分析框架，讨论从共享文件到跨应用横向移动的现实路径。

本文不虚构事件细节，不把架构可能性写成已发生的攻击。凡涉及 Coruna/DarkSword 的具体行为而公开资料未披露者，均明确标注“推断”或“公开资料未披露”。

## 关键词

iOS 容器；App Group；Data Protection；应用扩展；XPC；Universal Links；横向移动；Coruna；DarkSword

## 引言

应用数据容器是 iOS 安全模型中最容易被开发者低估、也最容易被攻击者利用的一层。开发者关心的是“文件写到哪里、备份会不会丢、审核能不能过”；攻击者关心的是“哪个目录里有令牌、哪个共享组跨越了信任边界、哪个扩展能在后台读文件”。两者关注点不同，但都指向同一组机制：容器路径、文件保护类、entitlement、进程边界与备份域。

App Group 的设计初衷是让主 App 与扩展、或同一开发者的多个 App 共享少量数据。它把“跨进程共享”简化为“共同拥有一个目录”，但也把“单点失陷”放大为“多点暴露”。只要一个带有 group entitlement 的组件被攻破，组内其它 App 写入的数据库、缓存、令牌与日志都可能被读取。更棘手的是，App Group 的成员关系通常不展示给用户，企业资产清单也未必记录。

本文先拆解容器布局与保护类，再讨论 App Group、扩展、XPC 与 Universal Links，随后给出横向移动的路径模型，并把 Coruna/DarkSword 的公开特征映射到数据收集阶段。最后给出可落地的开发、审计与 MDM 加固建议。

## 一、应用数据容器布局

### 1.1 两套容器：Bundle 与 Data

iOS App 安装后至少涉及两个容器。Bundle 容器位于 `/var/containers/Bundle/Application/<UUID>/<AppName>.app`，存放签名后的可执行文件、资源、框架与插件；它只读，更新时整体替换。Data 容器位于 `/var/mobile/Containers/Data/Application/<UUID>/`，存放运行时可写数据；它在 App 更新时保留，在卸载时删除，重装后 UUID 会变化。

Data 容器的 UUID 不是 Bundle ID，也不是稳定的设备标识。开发者不能用它做授权或去重；取证时也不能假设“上次看到的路径”仍然有效。相对地，Keychain 条目在卸载后可能继续存在，App Group 容器在组内最后一个 App 被删除后是否保留则随版本与安装路径而异。这些生命周期差异，正是备份、迁移与取证中最容易出错的地方。

开发 API 也不会直接暴露 UUID。`NSHomeDirectory()` 返回当前 App 的 Data 容器根目录，`FileManager.default.urls(for:in:)` 返回 `Documents`、`Library`、`Caches` 等标准目录，`NSTemporaryDirectory()` 返回 `tmp`。这些 API 在模拟器、真机与不同安装方式下返回的绝对路径不同，业务代码应只保存相对路径。取证工具则需要先从容器元数据或安装数据库解析 UUID，再映射到具体 App。

### 1.2 Documents、Library、tmp 的语义

Data 容器下的三个顶层目录具有不同语义。`Documents/` 存放用户产生的、应当保留的数据，默认参与 iCloud/iTunes 备份；若 App 启用 `UIFileSharingEnabled`，该目录会通过 Finder/iTunes 暴露；若启用 `LSSupportsOpeningDocumentsInPlace`，还会出现在“文件”App 中。`Documents/Inbox/` 用于接收其它 App 通过“打开方式”传入的文件，App 对其中文件通常只有读权限，需要移动或复制后才能修改。

`Library/` 存放 App 私有数据，常见子目录包括 `Preferences/`（UserDefaults 的 plist）、`Caches/`（可被系统清理、不备份）、`Application Support/`（需要保留的业务数据，默认备份）、`Cookies/`、`WebKit/` 等。`tmp/` 用于临时文件，系统可在 App 未运行时清理，不参与备份。很多数据泄露问题并不是“Documents 没加密”，而是“令牌被写进了 Caches 或 UserDefaults，既备份又被共享”。

各目录的工程语义可以进一步细化：

- `Documents/`：面向用户的数据，默认备份；若开启文件共享，任何能访问设备文件系统的人都可能看到。
- `Documents/Inbox/`：由“打开方式”写入，App 只有读权限；需要校验来源与类型，不能直接执行。
- `Library/Application Support/`：业务数据库、离线包、同步队列；默认备份，适合放需要恢复的数据。
- `Library/Caches/`：可重新生成的资源；系统可在存储紧张时清理，不应放唯一副本。
- `Library/Preferences/`：UserDefaults 的 plist；由 `cfprefsd` 管理，写入不是即时落盘。
- `tmp/`：短生命周期文件；App 退出后可能被清理，不能作为跨启动的持久化位置。

图 1 给出一个典型的容器布局。图中省略了系统注入的目录与符号链接，实际内容随 SDK、框架与 App 实现变化。

```text
/var/containers/Bundle/Application/<UUID>/Demo.app      (read-only, signed)
/var/mobile/Containers/Data/Application/<UUID>/          (per-install, writable)
+-- Documents/                     user data, backed up
|   +-- Inbox/                     incoming open-in files
+-- Library/
|   +-- Preferences/
|   |   +-- com.example.demo.plist UserDefaults
|   +-- Application Support/       business data, backed up
|   +-- Caches/                    purgeable, not backed up
|   +-- Cookies/                   web cookies
+-- tmp/                           purgeable, not backed up
+-- .com.apple.mobile_container_manager.metadata.plist
/var/mobile/Containers/Shared/AppGroup/<UUID>/           (shared by entitlement)
+-- Library/Preferences/group.com.example.demo.plist
+-- shared.sqlite                  often WAL mode
```

### 1.3 Data Protection classes

Data Protection 是 iOS 文件加密的核心。每个文件可以绑定一个保护类，类密钥由设备 UID 与用户密码派生，解锁状态决定类密钥是否可用。开发者通过 `NSFileProtectionKey`（Swift 中为 `FileAttributeKey.protectionKey`）或写入选项设置保护类，常见取值有四个。

`NSFileProtectionComplete`：文件仅在设备解锁时可读，锁屏后立即不可读。安全性最高，但后台任务、通知扩展、锁屏播放等场景可能失败。`NSFileProtectionCompleteUnlessOpen`：文件关闭后受保护，但已打开的文件在锁屏后仍可继续读写，适合长时下载与后台传输。`NSFileProtectionCompleteUntilFirstUserAuthentication`：设备首次解锁后即可读，直到重启；这是多数第三方 App 的默认类，也是后台访问与安全性的折中点。`NSFileProtectionNone`：不依赖用户密码，任何情况下可读，只应用于非敏感数据。

表 1 对比这四个类的行为。表中的“默认”指第三方 App 在未显式设置时的常见行为，实际以系统版本与 entitlement 为准。

| 保护类 | 锁屏后可读性 | 首次解锁后 | 备份行为 | 典型用途 |
|---|---|---|---|---|
| `NSFileProtectionComplete` | 否 | 需再次解锁 | 受备份加密保护 | 令牌、密钥材料、敏感文档 |
| `NSFileProtectionCompleteUnlessOpen` | 已打开文件可继续 | 是 | 受备份加密保护 | 后台下载、长连接缓存 |
| `NSFileProtectionCompleteUntilFirstUserAuthentication` | 是 | 是 | 受备份加密保护 | 多数 App 默认数据 |
| `NSFileProtectionNone` | 是 | 是 | 仅受备份加密保护 | 非敏感缓存、公开资源 |

开发者可以通过 `com.apple.developer.default-data-protection` entitlement 指定 App 的默认保护类，也可以在运行时逐文件设置。逐文件设置更灵活，但容易出现“新写的文件忘了设类”的回归问题。工程上应把保护类封装进统一的文件写入层，而不是在每个调用点复制字符串。

Keychain 的可访问性与文件保护类有对应关系，但并不完全相同。`kSecAttrAccessibleWhenUnlocked` 近似 `Complete`，`kSecAttrAccessibleAfterFirstUnlock` 近似 `CompleteUntilFirstUserAuthentication`，`kSecAttrAccessibleWhenUnlockedThisDeviceOnly` 在此之上禁止迁移到新设备。带 `ThisDeviceOnly` 的条目不会进入加密备份恢复，适合设备绑定的令牌。`SecAccessControlCreateWithFlags` 还可以要求 `userPresence`、`biometryCurrentSet` 或 `devicePasscode`；`biometryCurrentSet` 在指纹/面容重新录入后失效，适合高敏感操作。

锁屏状态需要通过 `UIApplication.shared.isProtectedDataAvailable` 或 `protectedDataAvailable` 通知来判断。后台任务在锁屏时读取 `Complete` 类文件会失败，开发者应把失败当作正常分支处理，而不是崩溃或静默丢数据。对必须后台完成的上传，应先把文件转为 `CompleteUnlessOpen` 或暂存到受控缓存，再在解锁后重新加密。

### 1.4 容器元数据与沙箱

Data 容器根目录下常见 `.com.apple.mobile_container_manager.metadata.plist`，其中记录容器标识、UUID、内容类等元数据，常见键包括 `MCMMetadataIdentifier`、`MCMMetadataUUID`、`MCMMetadataContentClass`。这些元数据由 `containermanagerd` 维护，App 不应修改；取证时可用于确认容器归属与类型。

沙箱通过 entitlement 与容器路径共同约束访问。App 默认只能访问自己的 Data 容器、只读的 Bundle 容器、以及系统明确允许的少数路径（如照片选择器返回的临时 URL）。当 App 调用 `FileManager.default.containerURL(forSecurityApplicationGroupIdentifier:)` 时，系统会检查其是否拥有对应的 App Group entitlement；没有 entitlement 时返回 `nil`，而不是抛出“权限不足”。这个细节常被开发者忽略，导致错误处理不完整。

## 二、App Group与共享容器

### 2.1 entitlement与容器解析

App Group 的核心是一个 entitlement：`com.apple.security.application-groups`，值为字符串数组，例如 `group.com.example.demo`。该数组会被写入 provisioning profile，并在安装时由代码签名与 `amfid` 校验。容器由 `containermanagerd` 创建，路径通常为 `/private/var/mobile/Containers/Shared/AppGroup/<UUID>/`，组 ID 与 UUID 的映射由系统数据库维护。

App 通过 `FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: "group.com.example.demo")` 获取共享目录，通过 `UserDefaults(suiteName: "group.com.example.demo")` 读写共享偏好。共享偏好实际落在组容器的 `Library/Preferences/group.com.example.demo.plist`，由 `cfprefsd` 缓存与合并。SQLite、文件缓存、日志等也可以放在组容器中，但是否适合共享，取决于数据的敏感度与并发模型。

App Group ID 的命名惯例是以 `group.` 开头，最终以开发者门户注册值为准。它不等同于 Bundle ID，也不等同于 Keychain access group。一个 App 可以属于多个 App Group；一个 Group 也可以被多个 App 与扩展共享。组成员越多，单点失陷的影响面越大。

组成员关系在安装时由 `installd` 与 `amfid` 校验，在运行时由容器管理守护进程解析。App 无法在运行时“申请加入”一个 group，也无法通过配置文件动态获得 group 访问权；group 必须出现在签名覆盖的 entitlement 中。这个设计阻止了普通 App 的越权，但也意味着“供应链污染”与“企业证书滥用”可以直接把恶意成员写进组里，而用户看不到任何提示。

企业审计时应把 group 当作“安全域”而不是“构建配置”。推荐的做法包括：

- 为每个业务域建立独立 group，例如文档、支付、日志各自一组。
- 禁止通用型 `group.com.company.all`，禁止第三方 SDK 自带 group。
- 主 App 与扩展的 group 列表保持最小交集，扩展只拿它真正需要的组。
- 在发布流水线中对比上一版本的 group 列表，新增即阻断。

### 2.2 共享容器的数据模式

共享容器最常见的三种数据模式是：偏好、文件与数据库。偏好适合少量配置，不适合令牌与大对象；文件适合文档、缓存与导出物；数据库适合结构化数据，但需要处理多进程并发。SQLite 在共享容器中通常启用 WAL 模式，读写并发更好，但要求所有进程对文件保护类、锁与崩溃恢复有共同理解。

多进程写入时，`NSFileCoordinator` 可以协调文件级访问，但它不是数据库事务的替代品。SQLite 自身提供锁与 WAL，开发者应使用 `sqlite3_open_v2` 的 `SQLITE_OPEN_FULLMUTEX` 或为每个连接串行化访问，并设置合理的 `busy_timeout`。若一个进程在锁屏时无法读取数据库（因为保护类为 `Complete`），另一个进程可能看到 `SQLITE_BUSY` 或解密失败；这类错误在测试中容易被忽略，在真实锁屏场景中却会集中出现。

共享容器的另一个陷阱是“默认保护类”。组容器中的文件不会自动继承某个统一的高保护类；如果写入时没有显式设置，可能落到 App 的默认类，甚至 `NSFileProtectionNone`。安全敏感的数据应逐文件设置保护类，并在读取时处理 `EACCES`/解密失败。

`UserDefaults(suiteName:)` 的写入由 `cfprefsd` 代理，调用返回并不代表已经落盘。跨进程读取时可能看到旧值，进程崩溃时也可能丢失最后一次写入。对一致性要求高的共享状态，应使用 SQLite 事务或带原子替换的文件写入（写入临时文件、`fsync`、`rename`），而不是依赖 plist 的“最终一致”。同时要注意，`UserDefaults` 的 suite 名称即使不存在的 group 也可能创建本地 plist；真正的共享必须同时满足 entitlement 与容器解析成功。

共享容器还需要明确的清理策略。登出、切换账号、远程擦除指令到达时，应删除组容器中的令牌、Cookie、导出文件与缓存，并调用 `CFPreferencesAppSynchronize` 或等价的同步接口确保 plist 落盘。仅删除数据库行而不清理 WAL/SHM 文件，可能让已删除的数据残留在磁盘上。

### 2.3 与Keychain access group的区别

App Group 共享的是文件，Keychain access group 共享的是钥匙串条目。后者的 entitlement 是 `keychain-access-groups`，查询时通过 `kSecAttrAccessGroup` 指定组。两者经常一起使用：文件里放业务数据，Keychain 里放解密密钥或令牌。但它们的生命周期与威胁模型不同。Keychain 条目在 App 卸载后可能保留；App Group 容器通常随 App 删除而清理（具体行为随版本与组状态而异）。Keychain 条目受 `SecAccessControl` 约束，可以要求生物识别或设备密码；App Group 文件只受 Data Protection 与沙箱约束。

表 2 对比 App Group、Keychain access group 与 Universal Links 三种跨边界机制。它们都可能被用于横向移动，但入口与约束完全不同。

| 机制 | 授权方式 | 作用域 | 生命周期 | 主要风险 |
|---|---|---|---|---|
| App Group | `com.apple.security.application-groups` | 组内 App 与扩展的文件 | 随安装/卸载与组状态变化 | 任一成员失陷导致共享数据暴露 |
| Keychain group | `keychain-access-groups` | 组内 App 的钥匙串条目 | 可能跨卸载保留 | 令牌被静默读取、访问控制配置过宽 |
| Universal Links | `com.apple.developer.associated-domains` + AASA | 域名到 App 的跳转 | 随 AASA 缓存与系统刷新 | 路径校验不严导致深链劫持或参数注入 |

## 三、应用扩展、XPC与URL Scheme/Universal Links

### 3.1 扩展的类型与容器

App 扩展以 `.appex` 形式放在主 App 的 `PlugIns/` 目录中，通过 `Info.plist` 的 `NSExtension` 声明类型。常见类型包括分享扩展（`com.apple.share-services`）、键盘扩展（`com.apple.keyboard-service`）、Widget（`com.apple.widgetkit-extension`）、通知服务扩展、文件提供者扩展与 Safari Web 扩展。每种扩展有独立的进程、独立的生命周期与内存限制，通常只有数十 MB 量级，超过限制会被 jetsam 终止。

扩展通常拥有自己的 Data 容器，但与主 App 共享 App Group。这个设计让扩展可以在不启动主 App 的情况下处理分享、通知或键盘输入，也让攻击者多了一个“后台可达”的入口。键盘扩展若启用 `RequestsOpenAccess`，可以获得网络访问与更完整的数据处理能力；用户需要在设置中明确授予“完全访问”。安全文本输入框不会把内容交给第三方键盘，但普通输入框、搜索框与部分自定义控件可能。

分享扩展接收其它 App 传入的 URL、文本、图片或文件；通知服务扩展可以修改远程通知的内容；文件提供者扩展可以枚举与读取其管理的目录。它们的共同点是“处理来自其它进程的数据”，因此必须把输入当作不可信：校验文件类型、限制大小、避免路径穿越、对解压/解码设置资源上限。

扩展的生命周期由系统控制，主 App 不能假设扩展常驻。分享扩展通常在用户完成分享后被终止；键盘扩展在切换输入法后可能被挂起；通知服务扩展有严格的执行时间预算。扩展通过 `NSExtensionContext.completeRequest(returningItems:completionHandler:)` 返回结果，通过 `open(_:completionHandler:)` 请求宿主打开 URL。任何跨进程传递的对象都应经过安全编码，避免把文件路径、数据库句柄或未验证的 URL 直接交给宿主。

扩展的 entitlement 应与主 App 分开审计。一个常见的错误是“主 App 不需要某 group，但扩展需要”，于是整个主 App 也被授予该 group；另一个错误是“扩展拥有网络权限，但只应处理本地文件”。最小权限应落实到每个 `.appex`，而不是只落实到主 App。

### 3.2 XPC与进程边界

XPC 是 iOS 上的进程间通信机制。App 内可以嵌入 `XPCServices/*.xpc`，通过 `NSXPCConnection(serviceName:)` 连接；系统守护进程可以通过 `xpc_connection_create_mach_service` 暴露 Mach service，客户端需要相应的 sandbox 与 entitlement 才能查找。`NSXPCListener` 在服务端接受连接，`NSXPCInterface.setClasses(_:for:argumentIndex:ofReply:)` 用于限制可反序列化的类，防止类型混淆。

XPC 的安全检查应发生在服务端，而不是客户端。服务端在接受连接时，应通过 audit token 获取客户端身份，校验其代码签名与 entitlement；`SecTaskCreateWithAuditToken` 与 `SecTaskCopyValueForEntitlement` 可用于读取客户端任务的权利信息（部分接口在 iOS 上属于受限/私有 API，使用前需验证可用性）。仅依赖“客户端会传正确的参数”是不够的：任何能连接到该服务的进程都可以构造任意参数。

App Group 不会自动授予 XPC 访问权。一个 App 即使与守护进程共享 group，也不能凭此连接对方的 Mach service；反之，XPC 客户端也不因为能连接服务就获得文件访问权。把“共享容器”与“共享 IPC”混为一谈，是设计评审中常见的错误。

### 3.3 URL Scheme与Universal Links

自定义 URL Scheme 通过 `Info.plist` 的 `CFBundleURLTypes` 声明。任何 App 都可以注册同一个 scheme，系统不保证唯一性；`canOpenURL` 需要把目标 scheme 加入 `LSApplicationQueriesSchemes`（数量上限为 50），而 `openURL` 在多个 App 注册同一 scheme 时的选择行为并不适合作为安全边界。因此，OAuth 回调、支付回调、密码重置等敏感流程不应只依赖自定义 scheme。

Universal Links 通过 `com.apple.developer.associated-domains` entitlement 与服务器上的 `apple-app-site-association`（AASA）文件建立关联。AASA 必须通过 HTTPS 提供在 `/.well-known/apple-app-site-association`，内容类型为 `application/json`，不能重定向，大小通常限制在 128 KB 以内。文件中的 `applinks` 包含 `details` 数组，每项有 `appIDs`（格式为 `TeamID.BundleID`）与 `paths` 或 `components`。`components` 从 iOS 13 起支持更细的匹配，包括 `"/": "/path/*"`、`"?": {...}`、`"#": {...}` 与 `exclude: true`。

Universal Links 的验证与缓存由 `swcd` 等系统组件负责。AASA 更新不会立即在所有设备生效；路径规则写得太宽（例如 `"/*"`）会把不该由 App 处理的 URL 也交给 App，增加参数注入与开放重定向的风险。OAuth 场景应使用 `ASWebAuthenticationSession`，并校验回调 URL 的 scheme、host 与 path，避免把授权码交给错误的 App。

一个最小化的 AASA 片段如下。示例只允许 `/docs/` 下的路径进入 App，并显式排除 `/oauth/`，避免把授权回调暴露给深链处理逻辑。

```json
{
  "applinks": {
    "details": [{
      "appIDs": ["ABCDE12345.com.example.app"],
      "components": [
        { "/": "/docs/*", "comment": "document links" },
        { "/": "/oauth/*", "exclude": true }
      ]
    }]
  }
}
```

AASA 是“域名到 App”的信任声明，不是“App 到域名”的授权。攻击者若控制了关联域名或 CDN，就可以修改 AASA，把链接导向恶意 App；因此，关联域名的 DNS、证书与发布权限应与主站同级保护。App 侧还应在打开深链后再次校验参数来源，不能因为“系统说这是 Universal Link”就默认可信。

图 2 展示从扩展与深链进入共享容器的典型路径。图中的“攻击者”可以是恶意 App、被供应链污染的 SDK，或一个被攻破的扩展。

```text
+---------------------+        +----------------------+
| Malicious app/SDK   |        | Victim app B         |
| group entitlement   |        | group entitlement    |
+----------+----------+        +----------+-----------+
           |                              |
           |  read/write                  |  read/write
           v                              v
+------------------------------------------------------+
| App Group container: shared.sqlite, tokens, caches  |
+------------------------------------------------------+
           ^
           |  same group
+----------+-----------+        +----------------------+
| Share/keyboard ext.  |        | URL scheme / Universal|
| (background reach)   |        | link -> app B        |
+----------------------+        +----------------------+
```

## 四、文件协调、备份与恢复

### 4.1 NSFileCoordinator与并发

`NSFileCoordinator` 用于协调同一文件在多个进程或线程之间的读写，常与 `NSFilePresenter` 配合。读操作使用 `coordinate(readingItemAt:options:error:byAccessor:)`，写操作使用对应的 writing 版本；`NSFileAccessIntent` 可以把多个访问合并为一个协调批次。协调器擅长处理“读写冲突、文件替换、iCloud 同步”等问题，但它不会自动加密文件，也不会替代数据库事务。

在共享容器中，常见的错误是“只用 `NSFileCoordinator` 保护 plist，却让 SQLite 直接并发写入”。正确做法是：文件型数据用协调器，数据库用 SQLite 自身的锁与 WAL；两者不要混用同一套假设。另一个错误是“在锁屏时后台写入 `Complete` 类文件”，导致写入失败却没有告警。应在写入层捕获错误、记录保护类与锁屏状态，并在下次解锁后重试。

协调器还可能引入死锁。若一个进程在持有协调器访问权时同步等待另一个进程的协调器回调，而对方又在等待同一文件，双方就会互相阻塞。避免方式包括：不在协调器回调里做同步 XPC、不为同一文件嵌套申请读写意图、为回调设置超时、把耗时操作移出回调。对共享数据库，优先使用数据库锁而不是文件协调器，减少跨进程等待。

`NSFileCoordinator` 与 iCloud/文件提供者的交互也需要测试。文件提供者可能在后台移动或替换文件，协调器会收到 `.delete`/`.move` 通知；若 App 缓存了文件描述符或绝对路径，可能在替换后读到旧内容。正确做法是每次通过协调器重新解析 URL，并在读取后校验文件代次或哈希。

### 4.2 备份的域模型

iCloud 备份与 Finder/iTunes 备份都会遍历 App 容器，把可备份的文件写入备份域。macOS 上的本地备份通常位于 `~/Library/Application Support/MobileSync/Backup/<UDID>/`，核心文件包括 `Manifest.db`、`Manifest.plist` 与 `Status.plist`。`Manifest.db` 的 `Files` 表通常包含 `fileID`、`domain`、`relativePath`、`flags` 与 `file` 等字段；`fileID` 常由 domain 与 relativePath 派生，`file` 字段存放文件内容或内容引用。`Properties` 表存放与备份相关的键值。

备份域通常包括 `AppDomain-<bundle-id>`、`AppDomainGroup-<group-id>`、`HomeDomain`、`CameraRollDomain`、`MediaDomain` 等。App Group 的数据会以 `AppDomainGroup-...` 形式进入备份；这意味着共享容器不仅暴露给组内 App，也可能暴露给任何能读取备份的人。若备份未加密，容器中的 plist、SQLite、缓存与日志都可以被离线解析。

备份是否加密由 `Manifest.plist` 中的 `IsEncrypted` 等字段体现。加密备份的密钥由设备密码与备份密码派生，取证工具需要密码才能解密；未加密备份则可以直接用 SQLite 打开 `Manifest.db`，并按 `domain` 与 `relativePath` 还原文件。企业应禁止未加密的本地备份，或至少要求备份介质全盘加密并限制访问。

```bash
#检查备份域与文件（在 macOS 备份目录中执行）
sqlite3 <UDID>/Manifest.db \
  "select domain, relativePath from Files where domain like 'AppDomainGroup-%' limit 20;"
plutil -p <UDID>/Manifest.plist | grep -i IsEncrypted
```

这段命令只用于取证与自查，不应在生产终端上随意执行。读取他人备份可能涉及隐私与法律问题，企业应在授权范围内操作，并记录证据链。

开发者可以通过 `URLResourceValues.isExcludedFromBackup` 或 `NSURLIsExcludedFromBackupKey` 把文件排除出备份。缓存、可重新下载的资源、临时导出物都应排除；令牌、密钥、审计日志是否备份，需要按业务与合规要求决定。把“所有文件都备份”当作默认，既浪费空间，也扩大泄露面。

### 4.3 恢复与容器迁移

恢复备份时，系统会为 App 创建新的 Data 容器 UUID，并把 `Manifest.db` 中的相对路径映射到新容器。绝对路径不应被写入数据库或配置文件；一旦写入，恢复后就会指向旧 UUID，导致“文件存在但读不到”。App Group 的组 ID 通常保持不变，但组容器的 UUID 可能变化；依赖绝对路径的共享逻辑同样会失效。

Keychain 条目的恢复行为取决于备份是否加密以及条目的可访问性。标记为 `ThisDeviceOnly` 的条目不会迁移到新设备；普通条目在加密备份恢复时可能迁移。企业应把“设备绑定”的令牌标记为 `ThisDeviceOnly`，并在恢复后强制重新认证，避免旧设备的令牌在新设备上继续有效。

图 3 展示备份域与容器迁移的关系。图中“新 UUID”是恢复后的容器，旧路径不应被业务代码硬编码。

```text
[App Data container <UUID-A>] --backup--> [Manifest.db]
       |                                      |
       |  domain: AppDomain-com.example.app   |
       |  domain: AppDomainGroup-group....    |
       v                                      v
[Files/ Manifest.plist] --restore--> [App Data container <UUID-B>]
       |
       +--> unencrypted backup: offline readable
       +--> encrypted backup: keybag-protected
```

## 五、从容器到横向移动的攻击路径

### 5.1 攻击者能力分级

讨论横向移动前，必须先界定攻击者的能力。否则“容器泄露”会被误写成“任意 App 数据可读”。可以粗略分为四级。T0：WebContent/JS 执行，受 WebKit 沙箱约束，通常不能直接读 App 容器。T1：以某个 App 身份执行，能读该 App 的 Data 容器与其 App Group。T2：以系统守护进程或拥有私有 entitlement 的进程执行，能读更多容器与数据库。T3：内核读写，绕过沙箱与代码签名，能读所有容器与 Keychain。

Coruna 的公开描述包含分阶段载荷，DarkSword 的公开描述强调纯 JS 协同；两者是否达到 T1/T2/T3，公开资料未披露。本文的路径分析不假设它们达到了某一级，而是说明“每一级能触达什么”。这个框架比具体归因更稳定。

需要强调的是，T1 与 T2 之间不是“多一个权限”那么简单。T2 往往意味着拥有私有 entitlement、能够连接系统服务、能够绕过部分 TCC 检查；这类能力通常来自内核漏洞、系统服务漏洞或供应链中的系统组件失陷，而不是普通 App 能通过配置获得的。T3 则完全绕过沙箱与代码签名，但仍受 SEP 与硬件绑定密钥保护的限制：内核读写不一定等于能解密 `Complete` 类文件，也不一定等于能导出安全隔区中的密钥。

### 5.2 四条典型路径

路径 A：共享组内的恶意 App。攻击者通过企业侧载、MDM 分发、开发者证书滥用或供应链 SDK，把一个带 `group.com.example.*` entitlement 的 App 装到设备上。该 App 不需要越狱，也不需要内核漏洞，就可以读取组容器中的 SQLite、plist、缓存与导出文件。若组内包含令牌或会话，攻击者可以直接调用云端 API。

路径 B：被攻破的扩展。分享扩展、键盘扩展或通知服务扩展通常在后台运行，拥有组容器的读写权。攻击者通过恶意输入（畸形文件、超大图片、深链参数）触发扩展中的解析漏洞，获得扩展进程执行权，再读取组容器。扩展的内存限制会限制利用稳定性，但“后台可达 + 共享容器”仍然具有吸引力。

路径 C：URL Scheme/Universal Link 劫持。攻击者注册与受害者相同的 scheme，或利用 AASA 的宽路径规则，诱导 OAuth 回调、魔法链接或支付回调进入恶意 App。攻击者不需要读容器，就能拿到授权码或令牌；随后用令牌访问云端数据。这条路线的本质是“凭据横向移动”，不是“文件横向移动”。

路径 D：备份与恢复。攻击者获得未加密的本地备份、iCloud 备份凭据或 MDM 备份导出，离线解析 `Manifest.db` 与容器文件。App Group 数据、UserDefaults、SQLite 与日志都可能被还原。对于企业设备，备份服务器与备份介质本身就是高价值目标。

这四条路径的检测线索不同。路径 A 应关注“新增 group 成员、异常证书、非受管安装”；路径 B 应关注“扩展崩溃、异常文件类型、后台网络请求”；路径 C 应关注“同 scheme 多 App 注册、AASA 宽路径、OAuth 回调异常”；路径 D 应关注“未加密备份、备份介质访问、恢复后新设备登录”。把四类线索混成一个“容器告警”，只会增加噪声。

### 5.3 构造性案例分析

假设某企业有一套内部 App：主 App 负责登录与文档，分享扩展负责导入，Widget 负责展示待办，三者共享 `group.com.corp.docs`。主 App 把会话令牌写入组容器的 `Library/Preferences/group.com.corp.docs.plist`，把文档缓存放进 `Library/Caches`，把审计日志放进 `Documents`。分享扩展启用后台处理，Widget 不访问网络。

若分享扩展被一个恶意文件触发解析漏洞，攻击者获得扩展进程执行权，就可以读取组容器中的令牌与缓存。即使主 App 的代码没有漏洞，即使设备没有越狱，攻击者也能以主 App 的身份调用文档 API。这个案例是构造性的，但它展示了 App Group 的核心风险：信任边界不是“App 边界”，而是“组边界”。

另一个构造性案例是“SDK 共用组”。某企业把多个内部 App 交给同一家外包商，外包商为了复用登录态，让所有 App 共享一个组。一个 App 被供应链污染，所有 App 的共享数据都暴露。修复方式不是“加强某一个 App 的审核”，而是“按业务域拆分 Group，按最小权限重新签发 profile”。

### 5.4 检测盲区

容器层的检测天然困难。iOS 不向企业 MDM 暴露 App 容器的文件清单，也不提供“哪个进程读了哪个文件”的审计日志。`sandbox` 拒绝通常只进系统日志，且不一定可见；`fs_usage` 是 macOS 工具，不能直接用于 iPhone。企业能做的，主要是安装前审计（entitlement、profile、SDK）、运行中网络检测（异常 API 调用、异常上传）、以及事件后的备份/日志取证。

这也是为什么“容器安全”必须前移到开发与发布流程。等到设备上出现异常，能拿到的往往只是网络流量与崩溃报告；文件级的证据可能已经被清理、覆盖或加密。

## 六、Coruna/DarkSword数据收集阶段的映射分析

### 6.1 公开描述的边界

公开分析对 Coruna 的描述包括 WebKit 入口、分阶段载荷与信息窃取模块；对 DarkSword 的描述包括纯 JavaScript 多漏洞协同、较少 Native Payload。两者都没有公开披露“读取了哪个 App Group”“使用了哪个容器路径”。因此，本节不做“它读了什么”的断言，而是做“在某一能力级别下，它理论上能读到什么”的映射。

这个区分很重要。安全团队常把“攻击者可能收集短信”写成“攻击者收集了短信”，再把“可能”丢掉，最后变成无法验证的 IOC。本文的映射表只用于设计检测与加固，不用于事件归因。

### 6.2 能力—数据矩阵

T0（WebContent/JS）：可触达的主要是当前网页会话、Cookie、LocalStorage、IndexedDB、缓存与同源网络请求。WebContent 进程有自己的沙箱与容器，不能直接读取其它 App 的 Data 容器。纯 JS 链条若未完成沙箱逃逸，其数据收集面主要限于 Web 数据；这与 DarkSword“较少 Native Payload”的公开特征在逻辑上一致，但具体行为公开资料未披露。

T1（App 身份）：可触达自己的 Data 容器、自己的 App Group、自己的 Keychain access group，以及通过系统 API 获得的有限数据（照片选择器、通讯录授权、日历授权等）。在公开取证资料中，短信数据库通常位于 `/private/var/mobile/Library/SMS/sms.db`，通讯录位于 `/private/var/mobile/Library/AddressBook/AddressBook.sqlitedb`，通话记录位于 `/private/var/mobile/Library/CallHistoryDB/CallHistory.storedata`；这些路径不属于普通 App 容器，普通 App 无权限直接读取。第三方 App 的共享组（例如公开资料常引用的 `group.net.whatsapp.WhatsApp.shared`）也只对拥有对应 entitlement 的 App 开放。

T2（系统守护进程/私有 entitlement）：可触达更多系统数据库与服务，包括短信、通话、账户、位置等，具体取决于 entitlement 与沙箱配置。T3（内核）：可绕过沙箱读取任意容器与 Keychain 数据库（`/private/var/Keychains/keychain-2.db`），但仍可能受 SEP、类密钥与硬件绑定保护的限制。

按数据类别看，可触达性大致如下。这些路径来自公开取证资料，实际权限随 iOS 版本变化，不能作为“任意 App 可读”的依据。

- Web 会话数据：Cookie、LocalStorage、IndexedDB、缓存；T0 可触达当前源，跨源受同源策略限制。
- 自身容器：Documents、Library、tmp；T1 可触达，受 Data Protection 与锁屏状态约束。
- App Group：共享数据库、plist、导出文件；T1 中拥有对应 entitlement 的成员可触达。
- 系统数据库：短信 `sms.db`、通讯录 `AddressBook.sqlitedb`、通话记录 `CallHistory.storedata`；通常需要 T2/T3 或特定授权。
- 照片与媒体：`/private/var/mobile/Media/DCIM`；普通 App 通过 Photos API 或选择器访问，不能直接枚举目录。
- Keychain：`keychain-2.db` 与安全隔区条目；T1 仅限自身 access group，T2/T3 也受类密钥与访问控制约束。

把 Coruna/DarkSword 映射到这个矩阵，可以得出一个克制结论：WebKit 入口本身不等于容器访问；分阶段载荷若在 App 上下文落地，才可能触达组容器；纯 JS 链条若停留在 WebContent，收集面主要是 Web 数据。公开资料未披露两者是否完成从 T0 到 T1/T2 的跨越，任何更具体的主张都需要独立证据。

### 6.3 容器为何是高价值低噪声目标

容器对攻击者的吸引力在于“低噪声”。读取文件不会触发权限弹窗，不会像麦克风/相机那样点亮指示灯，不会像通讯录那样留下 TCC 记录（若 App 已有权限）。共享容器中的 SQLite 往往包含结构化数据，易于解析；plist 中的令牌可以直接用于云端 API；缓存中的图片、PDF、日志可以用于情报分析。

容器也是“高价值”的，因为它承载了业务的真实状态：会话、草稿、离线文档、同步队列、审计日志。对商业间谍软件而言，这些数据的价值可能高于一次通话录音；对企业而言，这些数据一旦泄露，影响的是账户与业务，而不只是设备。

## 七、容器级检测与加固

### 7.1 开发侧：文件保护与密钥

开发侧的第一条建议是“敏感文件显式设置保护类”。写入时使用 `Data.write(to:options:.completeFileProtection)`，或用 `FileManager.createFile(atPath:contents:attributes:[.protectionKey: FileProtectionType.complete])`；对需要后台继续写的文件使用 `.completeUnlessOpen`；不要依赖默认类。读取时要处理锁屏导致的失败，并在解锁后重试。

第二条建议是“不要把令牌放进 UserDefaults 或 Caches”。UserDefaults 落在 `Library/Preferences/<bundle-id>.plist`，易被备份、易被组内其它进程读取；Caches 可能被系统清理，也可能被备份工具带走。令牌应放 Keychain，并使用 `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` 或 `SecAccessControl` 的生物识别/设备密码约束。需要跨设备同步的令牌，应使用可撤销、短时效的刷新令牌，而不是长期共享的静态密钥。

第三条建议是“共享容器最小化”。按业务域拆分 App Group，不要把所有 App 塞进一个 `group.com.company.all`；共享容器中只放确实需要共享的数据，敏感数据留在各自容器并用 Keychain 共享密钥；为共享文件设置统一的保护类与清理策略；在登出时清除组容器中的令牌、缓存与导出物。

### 7.2 entitlement审计

发布前应把 entitlement 审计做成流水线门禁。对每个 IPA，使用 `codesign -d --entitlements :- Payload/App.app` 导出 entitlement，使用 `security cms -D -i Payload/App.app/embedded.mobileprovision` 解析 profile，检查 `com.apple.security.application-groups`、`keychain-access-groups`、`com.apple.developer.associated-domains`、`com.apple.developer.default-data-protection` 是否符合白名单。对扩展，检查 `PlugIns/*.appex` 的 entitlement 是否与主 App 一致，是否存在不必要的组。

还应检查二进制中的组 ID 与域名。`strings` 可以快速发现硬编码的 `group.` 与 `applinks:`；`otool -L` 可以列出动态库，识别可疑 SDK；`nm -m` 可以查看符号暴露。对第三方 SDK，要求其提供 entitlement 变更说明，并在升级时做 diff。任何新增 App Group 都应触发人工评审，而不是被当作“构建配置”。

### 7.3 MDM与企业部署

MDM 不能读取 App 容器，但可以控制“哪些 App 能安装、哪些数据能流出”。建议启用 `allowOpenInManaged`，把“打开方式”限制在受管 App 之间；关闭不必要的 iCloud 备份（`allowCloudBackup=false`）或要求加密备份；限制 `allowAppInstallation` 与 `allowAppRemoval`，减少侧载与恶意替换；启用 `allowUSBRestrictedMode` 与 `allowHostPairing=false`，降低物理取证与配对攻击面；对 eSIM 与蜂窝配置使用 `allowESIMModification` 等限制。

对高敏感岗位，可以使用“受管 App + 每应用 VPN + 禁用剪贴板共享”的组合。受管 App 的数据不应出现在个人 App 的容器中；企业文档不应通过“打开方式”流入未受管 App。MDM 的应用配置（`com.apple.configuration.managed`）可以下发组 ID、环境与策略，但不要把密钥写进配置，因为配置本身可能被备份或读取。

### 7.4 检测与响应

检测应覆盖三个层面。安装前：entitlement 白名单、profile 有效期、证书来源、SDK 清单、App Group 成员图。运行中：异常网络请求（尤其是携带大量表单/文件的上传）、异常认证（新设备、新地理位置、非常用 API）、异常备份行为。事件后：sysdiagnose、崩溃报告、`Manifest.db`、容器备份、Keychain 条目（在授权与取证工具支持的前提下）。

响应时要注意“先固定证据，再清理”。删除 App 会删除其 Data 容器，但 Keychain 条目与 App Group 容器可能保留；抹掉设备会破坏现场。应先做备份与日志采集，再评估是否需要远程擦除。对确认泄露的令牌，立即在服务端撤销，而不是只改密码；对共享组中的其它 App，检查是否被同一凭证横向访问。

## 八、结语

iOS 的容器与 App Group 不是“一个 App 一个盒子”那么简单。它们是一组带有生命周期、保护类、entitlement 与备份语义的边界。边界之内，开发者拥有很大的自由；边界之间，系统只保证“有 entitlement 才能进”，不保证“进去的人值得信任”。这就是横向移动的根源。

对防守方而言，三条结论最值得记住。第一，容器安全的关键不是“是否加密”，而是“保护类是否与数据敏感度匹配、是否在锁屏与后台场景下仍然正确”。第二，App Group 是信任边界，不是便利设施；每增加一个成员，就增加一条失陷路径。第三，备份与恢复是容器的“第二生命”，未加密的备份会把端侧保护全部抹平。

Coruna 与 DarkSword 的公开特征提醒我们：攻击链的入口可能在 WebKit，但数据收集的落点一定在容器、数据库或网络。纯 JS 链条受 WebContent 沙箱约束，分阶段载荷则可能在 App 上下文获得更大的容器访问权；公开资料未披露两者的具体路径。防守方不应等待“确切的容器 IOC”，而应先把 entitlement 收紧、把保护类设对、把备份管住。这三件事不需要知道攻击者的名字，就能降低下一次事件的影响。
