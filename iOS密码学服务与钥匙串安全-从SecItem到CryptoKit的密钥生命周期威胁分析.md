# iOS密码学服务与钥匙串安全-从SecItem到CryptoKit的密钥生命周期威胁分析

## 摘要

iOS开发者常把Keychain理解为“系统提供的加密保险箱”，但Keychain真正的安全价值来自一组策略边界：securityd的 entitlement 检查、Data Protection的类密钥、Secure Enclave对ACL的判定，以及每行密文与元数据的分层加密。本文从Keychain与数据保护架构入手，拆解SecItem API的查询语义、kSecAttrAccessible保护类与SecAccessControl访问控制，分析Secure Enclave密钥与CryptoKit的适用边界，并给出覆盖生成、存储、使用、轮换、销毁的密钥生命周期模型。文章随后讨论access group、iCloud Keychain、备份与生物识别配置中的常见错误，并把Coruna与DarkSword公开描述中的凭证收集阶段映射到“Web会话—应用Keychain—SE密钥”三层能力模型。涉及未公开实现的部分均标注为推断。

## 关键词

Keychain；SecItem；Data Protection；Secure Enclave；CryptoKit；SecAccessControl；kSecAttrAccessible；access group；iCloud Keychain；密钥生命周期；Coruna；DarkSword

## 引言

“把密钥放进Keychain”是一句常见的工程建议，却经常掩盖真正需要回答的问题：这个item在锁屏时是否可读？它属于哪个access group？ACL要求的是生物识别、设备密码，还是两者之一？密钥材料是在应用进程里，还是在Secure Enclave里？备份、同步、恢复之后它是否仍然可用？如果应用进程被攻陷，攻击者能拿到明文，还是只能得到一个受使用策略约束的签名/解密接口？

本文以密钥生命周期为主线，讨论iOS密码学服务的使用方式与威胁边界。关于Secure Enclave的硬件隔离、启动链与物理攻击面，已有专文分析；本文只在它影响Keychain item与密钥可用性时展开。关于Coruna与DarkSword，本文只使用公开分析中的概括性描述，不虚构事件细节、不引用无法核实的编号。

## 一、Keychain与数据保护架构

### 1.1 组件与调用路径

应用调用`SecItemAdd`、`SecItemCopyMatching`、`SecItemUpdate`、`SecItemDelete`时，请求并不直接落在某个文件上。Security.framework把请求序列化后交给`securityd`；`securityd`根据调用进程的签名与entitlement判断它能否访问目标item，再与keybag、Secure Enclave协作完成解密。Apple平台安全文档给出的关键事实是：Keychain在iOS上是一个SQLite数据库，`securityd`根据应用的`keychain-access-groups`、`application-identifier`与`application-group` entitlement决定访问权。

```text
应用进程
  SecItemAdd / CopyMatching / Update / Delete
        |
        v
Security.framework（查询字典、ACL、LAContext）
        |
        v
securityd（XPC）
  - 校验代码签名与 entitlement
  - 解析 kSecClass / access group / 保护类
  - 查询 keychain-2.db
        |
        +--> keybagd / AKS：类密钥、锁屏状态、备份keybag
        |
        +--> Secure Enclave
               - ACL 判定（用户在场、生物识别、当前录入集合）
               - 类密钥/每行密钥的解封
               - 生物特征匹配
        |
        v
返回属性、密钥引用或解密后的 kSecValueData
```

这条路径解释了为什么“有root/kernel读写”不必然等于“读出所有Keychain明文”：secret value的每行密钥需要SEP参与，ACL也在SEP内判定；但metadata与类密钥的缓存策略、以及securityd自身的可信度，决定了攻击者在内核失陷后能走多远。后文会分开讨论。

### 1.2 两层密文：元数据与secret

Apple平台安全文档对Keychain加密结构的描述很具体：每个item使用两个AES-256-GCM密钥，一个表密钥（table key）保护元数据，一个每行密钥（per-row key）保护secret。元数据包括除`kSecValueData`之外的大多数属性，加密后用于快速搜索；表密钥由Secure Enclave保护，但会缓存在Application Processor上以加速查询；每行密钥则始终需要一次Secure Enclave往返。

这个设计带来两个重要推论：

- 元数据与secret的暴露面不同。元数据密钥在AP缓存，意味着在特定攻击模型下，账户名、服务名、访问组、创建时间等属性可能比secret更容易被枚举；secret仍受类密钥、SEP与ACL约束。
- “Keychain数据库被拷走”不等于“secret被解密”。数据库里是密文，每行密钥的解封依赖SEP与类密钥；但若攻击者同时掌握已解锁设备、类密钥与securityd的调用能力，边界会显著变窄。

Keychain的保护类与文件Data Protection类平行，但使用不同的密钥与函数。文件类保护的是文件内容，Keychain类保护的是item的secret与元数据；两者不能混为一谈，也不能用`NSFileProtection`的直觉推断Keychain item在锁屏时的行为。

### 1.3 保护类与锁屏状态

Keychain的可用性由保护类、锁屏状态、keybag与ACL共同决定。最常用的两个类是`kSecAttrAccessibleWhenUnlocked`与`kSecAttrAccessibleAfterFirstUnlock`；前者只在设备解锁时可用，后者在首次解锁后直到重启前都可用。`kSecAttrAccessibleAlways`已被废弃，不应在新代码中使用。`kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`更严格：它只在设备设置了密码时存在，不参与iCloud同步、不进入备份、不进入escrow keybag；密码被移除或重置时，系统丢弃对应类密钥，item随之失效。

| Keychain保护类 | 文件类对照 | 密钥可用性 | 迁移/备份行为 | 适用场景 |
|---|---|---|---|---|
| `kSecAttrAccessibleWhenUnlocked` | `NSFileProtectionComplete` | 仅解锁时 | 非ThisDeviceOnly可随备份迁移 | 前台使用、低延迟读取 |
| `kSecAttrAccessibleAfterFirstUnlock` | `NSFileProtectionCompleteUntilFirstUserAuthentication` | 首次解锁后至重启 | 非ThisDeviceOnly可随备份迁移 | 后台刷新、短期令牌 |
| `kSecAttrAccessibleAlways`（已废弃） | `NSFileProtectionNone` | 始终 | 可迁移 | 不应使用 |
| `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` | 对应Complete类，需密码 | 设置密码且解锁时 | 不同步、不备份、不托管 | 高价值、设备绑定secret |
| `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` | Complete | 仅解锁时 | UID绑定，备份不可迁移 | 设备绑定密钥 |
| `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` | UntilFirstUserAuthentication | 首次解锁后至重启 | UID绑定，备份不可迁移 | 后台令牌、设备绑定 |

表中“可迁移”不等于“一定会被备份”。是否进入iCloud Backup、加密本地备份或iCloud Keychain，还取决于item是否设置`kSecAttrSynchronizable`、设备管理策略与备份类型。工程上应把“设备绑定”和“后台可用”作为两个独立维度设计，而不是用一个`AfterFirstUnlock`包打天下。

### 1.4 Keybag、锁屏与首次解锁

Keychain的类密钥来自keybag。用户密码解锁user keybag；设备keybag承载设备级密钥；备份keybag用于加密备份；iCloud Keychain另有同步与恢复机制。设备重启后，`WhenUnlocked`类item在首次解锁前不可用；`AfterFirstUnlock`类item在首次解锁后可用，直到再次重启；`WhenPasscodeSetThisDeviceOnly`依赖系统keybag中的类密钥，密码移除即失效。

这也是为什么“后台任务能读到token”与“锁屏时能读到token”不是同一个问题。前者可能只需要`AfterFirstUnlock`，后者需要`Always`（已废弃）或特定系统能力；如果业务不需要后台读取，使用`AfterFirstUnlock`只会扩大攻击窗口。

## 二、SecItem API与访问控制

### 2.1 API表面与查询语义

SecItem的四个核心API各有明确的查询/更新语义：

- `SecItemAdd(attributes, result)`：创建item。attributes必须包含`kSecClass`，以及该class要求的属性（如`kSecAttrService`/`kSecAttrAccount`）和值（`kSecValueData`或密钥属性）。重复添加返回`errSecDuplicateItem`。
- `SecItemCopyMatching(query, result)`：按query查找。`kSecReturnData`、`kSecReturnAttributes`、`kSecReturnRef`决定返回内容；`kSecMatchLimitOne`/`kSecMatchLimitAll`决定数量；`kSecUseAuthenticationContext`传入`LAContext`；`kSecUseAuthenticationUI`控制是否允许弹窗。
- `SecItemUpdate(query, attributesToUpdate)`：更新已有item的属性或数据。不要依赖它迁移`kSecClass`或access group；需要迁移时应删除重建，并处理失败回滚。
- `SecItemDelete(query)`：按query删除。query过宽会误删同组item；生产代码应使用service/account/access group等稳定标识。

`kSecClass`的常见取值包括`kSecClassGenericPassword`、`kSecClassInternetPassword`、`kSecClassKey`、`kSecClassCertificate`、`kSecClassIdentity`。密码/token通常放`GenericPassword`；密钥引用或SE密钥放`Key`；证书与身份放对应class。不同class支持的属性不完全相同，跨class复制不能想当然。

### 2.2 kSecAttrAccessible与ACL的关系

`kSecAttrAccessible`描述“什么时候可以访问”，`kSecAttrAccessControl`描述“访问时需要什么认证”。二者不要同时设置：ACL本身包含保护类，混用会让代码难以推理，且在不同系统版本上可能得到非预期结果。需要生物识别/密码约束时，用`SecAccessControlCreateWithFlags`创建ACL并放入`kSecAttrAccessControl`；只需要锁屏策略时，用`kSecAttrAccessible`。

`SecAccessControlCreateWithFlags`的典型调用如下（示意，不是完整错误处理）：

```swift
var error: Unmanaged<CFError>?
let acl = SecAccessControlCreateWithFlags(
    nil,
    kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
    [.biometryCurrentSet, .privateKeyUsage],
    &error
)
```

这段代码表达的是：item只在设置密码且解锁时可用；私钥操作要求当前录入的生物特征集合；不允许用新增指纹/面容绕过。该ACL组合用于SE私钥item；普通密码item不要加`.privateKeyUsage`，否则可能得到`errSecParam`。若把`.biometryCurrentSet`换成`.biometryAny`，新增录入的生物特征仍可解锁同一item；若换成`.userPresence`，设备密码可作为回退。两者的安全语义差别很大，不能只看“都弹了生物识别框”。

### 2.3 ACL标志的语义

ACL在Secure Enclave内判定，只有满足约束时才把结果释放给内核。这意味着ACL不是应用层的“提示框逻辑”，而是密钥使用路径的一部分。常见标志如下：

| ACL标志 | 认证因素 | 录入变化后的行为 | 典型用途 |
|---|---|---|---|
| `.userPresence` | 生物识别或设备密码 | 仍可用（受当前录入/密码影响） | 平衡安全与可用性 |
| `.biometryAny` | 任一已录入生物特征 | 新增录入仍可访问 | 低摩擦解锁 |
| `.biometryCurrentSet` | 仅当前录入的生物特征集合 | 录入变化后item失效/需重建 | 高价值密钥 |
| `.devicePasscode` | 仅设备密码 | 密码移除/重置影响类密钥 | 无生物识别场景 |
| `.applicationPassword` | 应用提供的附加密码 | 由应用管理 | 二次保护 |
| `.privateKeyUsage` | 约束SE私钥操作 | 与认证标志组合 | 签名/解密需授权 |

`.privateKeyUsage`不是认证因素，而是“私钥使用”约束；它常与`.biometryCurrentSet`或`.userPresence`组合。对Secure Enclave密钥，如果只设置`.privateKeyUsage`而不加用户在场约束，密钥操作可能不需要每次认证；具体行为取决于item的ACL组合与Keychain访问路径，应在目标系统上验证，不能凭直觉假设“SE密钥一定每次弹窗”。

### 2.4 LAContext、弹窗与复用窗口

`LAContext`用于评估生物识别/密码策略，并通过`kSecUseAuthenticationContext`传入SecItem查询。常用属性包括`canEvaluatePolicy`、`evaluatePolicy`、`biometryType`、`localizedFallbackTitle`，以及`touchIDAuthenticationAllowableReuseDuration`。后者允许在短时间内复用上一次认证结果，系统上限约为5分钟（常量`LATouchIDAuthenticationMaximumAllowableReuseDuration`）。

复用窗口是典型的“安全与体验”折中：窗口越长，用户在后台被诱导一次认证后，攻击者可在窗口内重复使用密钥；窗口为0则每次操作都要认证，可能造成弹窗疲劳。高价值操作应使用短窗口或每次认证，并把认证与具体操作绑定（例如在AAD中绑定交易ID），而不是拿到一个“已认证”状态后任意使用。

`kSecUseAuthenticationUI`可以控制是否允许UI。设置为`kSecUseAuthenticationUIFail`时，需要认证的查询会返回`errSecInteractionNotAllowed`而不是弹窗；这适合后台探测item是否存在，但也可能被滥用来枚举元数据。应用应明确：哪些查询允许弹窗，哪些查询在后台必须失败，不能把“失败”误判为“item不存在”。

### 2.5 访问决策流程

把上述因素串起来，一次`SecItemCopyMatching`的决策大致如下：

```text
SecItemCopyMatching(query)
        |
        v
securityd: 解析 kSecClass / service / account / access group
        |
        v
entitlement 检查：keychain-access-groups / application-identifier
        |
   +----+----+
   |         |
 不通过     通过
   |         |
   v         v
errSec    保护类/keybag：当前锁屏状态是否允许类密钥？
Missing      |
Entitlement  +----+----+
                  |    |
                不允许 允许
                  |    |
                  v    v
          errSec     有ACL？--否--> 解封每行密钥 -> 解密 -> 返回
          Interaction   |
          NotAllowed   是
                        |
                        v
                 SEP判定：用户在场/生物识别/当前集合
                        |
                   +----+----+
                   |         |
                 不满足      满足
                   |         |
                   v         v
             errSecAuth  解封/使用密钥 -> 返回
             Failed
```

这条流程里，任何一层失败都不应被应用“降级处理”。例如，ACL认证失败时改用软件密钥、把secret搬到`UserDefaults`、或关闭`ThisDeviceOnly`后重试，都会把一次受控失败变成长期弱点。

## 三、Secure Enclave密钥与CryptoKit

### 3.1 SE密钥的生成与使用

在iOS上，Secure Enclave对应用暴露的非对称密钥能力以NIST P-256为主。用Security.framework生成SE密钥时，典型属性组合是：`kSecAttrKeyType`为`kSecAttrKeyTypeECSECPrimeRandom`，`kSecAttrKeySizeInBits`为256，`kSecAttrTokenID`为`kSecAttrTokenIDSecureEnclave`，私钥属性中包含`kSecAttrIsPermanent`、`kSecAttrAccessControl`与`kSecAttrApplicationTag`。RSA与Ed25519等算法不能依赖SEP生成/保管私钥；需要这些算法时，应明确密钥在应用进程内，而不是“在SE里”。

SE私钥不可导出。`SecKeyCopyExternalRepresentation`对SE私钥会失败；可以导出的是公钥。签名通常走`SecKeyCreateSignature`与`SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256`，ECDH走`SecKeyCopyKeyExchangeResult`或CryptoKit的KeyAgreement接口。私钥 material 留在SEP内，应用拿到的是密钥引用与操作结果。

### 3.2 CryptoKit的三种密钥形态

CryptoKit把常见原语封装成值类型，但“用CryptoKit”不等于“密钥受硬件保护”。至少有三类形态：

```text
SecureEnclave.P256.Signing.PrivateKey
  - 私钥在SEP内生成/使用
  - 仅P-256；不可导出；受ACL约束
  - dataRepresentation是受SEP保护的包装，可持久化
  - 适合设备绑定签名/密钥协商

P256.Signing.PrivateKey / Curve25519.Signing.PrivateKey
  - 私钥字节在应用进程内
  - 可导出rawRepresentation；算法选择更多
  - 适合临时会话密钥/可迁移场景
  - 进程被攻陷/崩溃转储时风险高

SymmetricKey
  - 原始对称密钥字节，AES-GCM/ChaChaPoly/HKDF使用
  - CryptoKit提供容器与API，不提供SEP式硬件边界
  - 应使用SEP/Keychain中的KEK做信封加密
```

`SecureEnclave.P256.Signing.PrivateKey(accessControl:)`与`SecureEnclave.P256.KeyAgreement.PrivateKey`是CryptoKit的SE接口；`SecureEnclave.isAvailable`在模拟器上为false。`dataRepresentation`可以存入Keychain或文件，但它不是明文私钥，且绑定设备/SEP；换设备后不能期望恢复。若需要跨设备使用，必须设计密钥包装/轮换，而不是复制SE密钥。

`SymmetricKey`的内存生命周期也值得注意。CryptoKit的容器会尽量减少明文暴露，但它不是“不可提取”的硬件密钥；Swift的值语义、复制、崩溃报告、日志与调试器都可能留下副本。高价值对称密钥应放在SEP保护的KEK之下，用时解封、用完丢弃，并避免`print`、`os_log`默认公开字段、异常上报中携带密钥材料。

### 3.3 CryptoKit的算法边界

CryptoKit提供`AES.GCM`、`ChaChaPoly`、`P256`、`Curve25519`、`HKDF`、`SHA256`等常用原语。工程上应把它们用于“正确的用途”，而不是把同一个密钥复用到所有用途：

- 加密：`AES.GCM.seal`/`open`，随机nonce由CryptoKit生成；不要把`combined`里的nonce重复用于同一密钥。
- 认证加密的附加数据：把item ID、版本、用户/设备上下文放入`authenticating`，防止密文被跨上下文替换。
- 密钥派生：`HKDF<SHA256>.deriveKey(inputKeyMaterial:salt:info:outputByteCount:)`，用不同的`info`做密钥分离（加密、签名、索引）。
- 签名：`P256.Signing`用于ECDSA；`Curve25519.Signing`用于Ed25519；SE路径只支持P-256。
- 哈希/口令：不要用SHA256直接存密码；使用系统口令哈希/密钥派生，按业务需求选择PBKDF2/Argon2等（CryptoKit本身不提供口令KDF，需另行实现或调用系统接口）。

## 四、密钥生命周期管理

### 4.1 生命周期模型

把密钥当作有生命周期的资产，而不是一个常量字符串，能消除大量“配置正确但架构错误”的问题。一个可审计的模型至少包含：

```text
生成            存储              使用              轮换/销毁
  |               |                 |                  |
熵源/算法       Keychain/SEP       ACL/认证           版本化key ID
  |               |                 |                  |
用途分离      保护类/access group  AAD/nonce          重加密/撤销
  |               |                 |                  |
密钥ID/标签    备份/同步策略       错误处理           删除/ crypto erase
```

### 4.2 生成：熵、用途与标识

使用`SecRandomCopyBytes(kSecRandomDefault, count, buffer)`或CryptoKit的密钥初始化器生成密钥；不要用时间戳、设备ID、用户ID或低熵口令派生“看起来随机”的密钥。每个用途生成独立密钥：加密密钥、签名密钥、索引密钥、会话密钥分开；用`kSecAttrApplicationTag`/`kSecAttrLabel`/`kSecAttrService`建立稳定标识，避免用account字段承载版本信息。

对SE密钥，生成时就应确定ACL与保护类；生成后再改ACL通常需要重建item。对对称密钥，先生成DEK，再用SEP中的KEK包装；不要把KEK与DEK存在同一个保护域。

### 4.3 存储：Keychain、SEP与信封加密

存储位置应按威胁模型分层：

- 低价值、可重建的token：Keychain `GenericPassword`，`AfterFirstUnlock`，按需设置access group。
- 高价值、设备绑定的secret：`WhenPasscodeSetThisDeviceOnly`或`WhenUnlockedThisDeviceOnly`，必要时加ACL。
- 长期签名/协商密钥：SEP P-256，`.privateKeyUsage` + `.biometryCurrentSet`/`.userPresence`，私钥不出SEP。
- 大量数据加密：DEK用`AES.GCM`/`ChaChaPoly`，DEK由SEP/Keychain中的KEK包装；密钥层级与数据分离。

不要把secret放进`UserDefaults`、plist、`NSUserActivity`、剪贴板、日志或崩溃上下文。`UserDefaults`是明文plist；剪贴板可被其他应用/系统组件读取；日志会进入sysdiagnose。即使Keychain item配置正确，这些旁路也会让密钥生命周期管理失效。

### 4.4 使用：最小权限与错误处理

使用密钥时，最小权限体现在三处：access group尽量窄、ACL尽量贴近操作、认证窗口尽量短。每次敏感操作都应重新评估是否需要认证；不要把`LAContext`的“成功”缓存成全局布尔值。对解密失败、ACL失败、锁屏不可用分别处理：`errSecInteractionNotAllowed`表示当前状态不允许交互，不应降级到软件密钥；`errSecAuthFailed`表示认证失败，不应无限重试导致锁定/弹窗疲劳；`errSecItemNotFound`可能意味着item不存在，也可能意味着查询条件/access group不对，不能一律当成“首次启动”。

加密数据应绑定上下文：AAD包含item ID、版本、用户/租户标识；解密时验证版本与上下文，拒绝跨租户/跨item的密文替换。Nonce必须唯一；随机nonce由CryptoKit生成，若使用计数器则必须持久化并防止回滚。

### 4.5 轮换：版本化与重加密

轮换不是“生成新密钥就完事”。需要：为密钥分配可持久化的key ID；密文头部记录key ID与算法版本；新数据用新密钥，旧数据可读；后台重加密完成后再退役旧密钥；服务端同步撤销旧token/旧公钥。轮换期间要允许双版本共存，但必须限制旧密钥的使用范围与时长。

对SE密钥，轮换意味着生成新key pair、注册新公钥、给旧公钥设退役时间；私钥不能导出，所以“迁移”实际上是“重新注册”。对对称密钥，轮换意味着重新包装DEK或重新加密数据；不要只替换Keychain item而保留旧密文。

### 4.6 销毁：删除、撤销与备份残留

`SecItemDelete`删除Keychain item；SE密钥随item删除而失效；服务端应同时撤销对应token/公钥。iOS的闪存/APFS不适合“覆写磁盘”，销毁应依赖crypto erase与密钥删除，而不是多次写0。需要检查：加密备份、iCloud Keychain、企业备份、日志、缓存、崩溃报告是否仍保留旧密钥或旧密文；`ThisDeviceOnly`与`WhenPasscodeSetThisDeviceOnly`能减少迁移残留，但不能替代服务端撤销。

## 五、常见配置错误与滥用路径

### 5.1 access group过宽

Keychain item通过`kSecAttrAccessGroup`共享。默认group是应用的application-identifier；共享group必须出现在代码签名entitlement中，并且只能在同一开发者前缀下使用。常见错误是把所有应用、扩展、测试工具放进同一个group，导致任何一个被攻陷的组件都能读取全部secret。更隐蔽的错误是：主应用使用窄group，扩展使用宽group，攻击者从扩展切入。

修复方式：按“最小共享”划group；把登录token、支付密钥、分析标识分到不同group；定期审计provisioning profile与entitlement；对不再使用的共享group删除item并重建。不要用access group做“租户隔离”，它不是为多租户设计的。

### 5.2 iCloud Keychain与synchronizable

`kSecAttrSynchronizable = true`会让item参与iCloud Keychain同步。Apple的设计目标是端到端加密：item在设备间传输时加密，Apple无法读取云端内容，只有用户授权的受信设备在本地解密；iCloud Keychain还设计为在Apple Account被攻陷、iCloud被外部攻击者/员工访问、第三方访问用户账户等情况下仍保护密码与passkey。但这不等于“开了同步没有代价”：同步扩大了item可出现的设备集合，恢复/escrow流程引入了额外的信任主体，设备丢失/账户恢复策略也会改变攻击面。

设备绑定secret不应设置`synchronizable`，也不应与`ThisDeviceOnly`混用。高价值item优先`WhenPasscodeSetThisDeviceOnly`；需要跨设备时，使用独立的、可轮换的同步密钥，并把服务端撤销作为第二道控制。

### 5.3 备份与恢复

`ThisDeviceOnly` item在备份复制时用UID保护，恢复到另一台设备后不可用；`WhenPasscodeSetThisDeviceOnly`不进入备份、不同步、不进入escrow keybag。非ThisDeviceOnly item可能随加密备份迁移，具体取决于备份类型与策略。常见错误是：开发者为了让用户换机后“无感”，把所有token都设为可迁移，结果备份文件成为凭证仓库；或者反过来，所有item都ThisDeviceOnly，导致用户换机后无法恢复、业务被迫降级到弱认证。

修复方式：按“可重建/不可重建”分类；不可重建的密钥设计迁移/重新注册流程；可重建的token设置短有效期与服务端撤销；备份策略与MDM策略一起评审，而不是只改一个属性。

### 5.4 ACL配置与生物识别降级

常见错误包括：用`.userPresence`却假设“只能生物识别”（设备密码可回退）；用`.biometryAny`却假设“新增录入会失效”（不会）；把`localizedFallbackTitle`设为空就以为禁用了密码回退（UI隐藏不等于策略禁止）；把`LAContext`复用窗口设得很长，导致一次认证后长时间可用的“授权窗口”；在SE密钥上只设`.privateKeyUsage`而不加用户在场约束。

修复方式：高价值item使用`.biometryCurrentSet` + `.privateKeyUsage`；明确是否需要密码回退；把认证与具体交易/操作绑定；对 enrollment 变化做失效处理与重新注册引导；在真机上测试锁屏、重启、密码移除、录入变更、备份恢复等状态。

### 5.5 应用卸载、日志与旁路

Keychain item通常不会随应用卸载自动删除（历史行为，受系统版本与配置影响），重新安装后可能读到旧secret。若业务要求“卸载即清除”，需要在首次启动用安装标记清理，但要避免误删共享group中其他应用的数据。另一个常见旁路是日志：`print`、默认`os_log`字段、崩溃上报、网络调试代理可能携带token/密钥；应使用隐私标记、脱敏与采样，避免把secret写入任何持久化日志。

### 5.6 密钥复用与算法混淆

把同一个Keychain secret同时用于加密、签名、索引、设备标识，会让一次泄露扩散到多个信任域；把`kSecAttrAccessible`当成ACL、把`kSecAttrAccessControl`当成保护类、把SE密钥当成“更安全的软件密钥”，都是常见的概念混淆。修复方式：按用途分离密钥；用HKDF的`info`做域分离；在密文头记录算法与版本；对SE密钥的能力边界（仅P-256、不可导出、操作受ACL约束）做明确文档。

## 六、Coruna/DarkSword凭证收集阶段的映射分析

### 6.1 公开描述与未知边界

公开分析通常把Coruna描述为以WebKit远程入口为起点、使用分阶段载荷、具备较强的原生执行与后渗透能力；把DarkSword描述为以纯JavaScript协同多个漏洞、较少依赖传统Native Payload。两者都被放在商业间谍软件/高级攻击链的语境中讨论，凭证收集是常见的后渗透目标之一。但公开资料并未披露它们是否读取Keychain、读取了哪些保护类、是否使用access group、是否绕过ACL；把这些细节当作既成事实是不严谨的。

因此，下面的映射是“能力模型”而非“事件复现”：它回答的是“若攻击者要达到某一层凭证，需要具备什么条件”，而不是“某代号已经做到了什么”。

### 6.2 三层凭证模型

```text
第一层：Web会话数据
  cookies / localStorage / IndexedDB / 缓存 / autofill 表单
  位置：WebContent或应用WebView进程
  条件：WebKit RCE或应用内JS执行；不需要Keychain权限

第二层：应用Keychain item
  位置：keychain-2.db + securityd + keybag
  条件：在具有对应entitlement的进程内执行；设备解锁/类密钥可用；
        access group匹配；ACL满足（或item无ACL）
  结果：metadata、secret明文或密钥引用

第三层：Secure Enclave密钥
  位置：SEP
  条件：拿到密钥引用；ACL满足；用户在场/生物识别
  结果：签名/解密操作，不是私钥导出
```

这三层的攻击成本差异很大。第一层只需要WebContent内的代码执行；第二层需要“应用上下文 + entitlement + 解锁状态 + ACL”；第三层即使拿到内核读写，也不自动获得私钥明文，只能尝试在ACL允许的范围内使用密钥。

### 6.3 映射到Keychain生命周期

以下映射是按能力条件推导的防御性分析，不是对已披露事件的复述。

- 收集阶段：攻击者首先寻找Web会话token、cookie、localStorage，这类数据不经过Keychain；若载荷运行在应用进程且拥有access group，才可能调用`SecItemCopyMatching`读取第二层。
- 解锁阶段：`WhenUnlocked` item需要设备解锁；`AfterFirstUnlock`在首次解锁后可用；`WhenPasscodeSetThisDeviceOnly`还要求密码存在。攻击者若只控制WebContent，通常无法直接触发securityd的Keychain查询。
- ACL阶段：带`.biometryCurrentSet`/`.userPresence`的item需要SEP判定与用户交互；后台静默读取会得到`errSecInteractionNotAllowed`或`errSecAuthFailed`。攻击者可以通过钓鱼/界面诱导用户认证，但这属于用户交互攻击，不是纯内存利用。
- SE阶段：SE私钥不可导出；攻击者能做的是调用签名/解密接口。若ACL允许且用户在场，这会变成“密钥使用攻击”；若ACL严格，收益有限。
- 外传阶段：拿到secret后仍需网络外传；服务端令牌撤销、设备绑定、短有效期会限制其价值。

### 6.4 对两个代号的推断

从能力模型看，Coruna式“分阶段 + 原生载荷”更有可能在沙箱逃逸后进入应用上下文，从而触及第二层Keychain；DarkSword式“纯JS + 少Native Payload”更自然地停留在第一层Web会话数据，除非它后续取得了应用进程执行或系统服务访问。两者都不太可能“直接读出SE私钥”，因为SEP的设计目标就是让私钥不可导出；更现实的是在ACL允许时滥用密钥操作，或窃取SE密钥所保护的上层token。

这只是推断。公开资料未披露它们的Keychain访问路径、access group、ACL配置与用户交互策略；防御者不应根据代号假设攻击者“只能偷cookie”或“一定能读Keychain”，而应按三层模型分别布防。

### 6.5 为什么“内核读写”不等于“Keychain明文”

Apple的文档明确指出：secret的每行密钥始终需要SEP往返，ACL在SEP内判定。即使攻击者获得内核读写，若SEP拒绝解封、ACL不满足，secret仍不可读；metadata key在AP缓存，可能先暴露元数据，但这与secret明文是两件事。内核攻击者可以尝试篡改securityd、注入具有entitlement的进程、或等待设备解锁，但这些都需要额外能力，且会留下不同痕迹。公开资料未披露Coruna/DarkSword是否具备这些能力，本文不做断言。

## 七、检测与加固

### 7.1 开发者检查清单

- 保护类：高价值secret使用`WhenPasscodeSetThisDeviceOnly`或`WhenUnlockedThisDeviceOnly`；后台token才考虑`AfterFirstUnlock`；禁止`Always`。
- ACL：高价值密钥使用`.biometryCurrentSet` + `.privateKeyUsage`；明确是否允许设备密码回退；不要把UI隐藏当策略。
- 访问组：按最小共享划分`keychain-access-groups`；主应用/扩展/测试工具不共用宽group；审计entitlement。
- 同步/备份：设备绑定item禁用`synchronizable`；需要跨设备时设计独立密钥与重新注册，不复制SE密钥。
- 加密：AES-GCM/ChaChaPoly使用唯一nonce；AAD绑定item/版本/租户；DEK由SEP/Keychain中的KEK包装。
- 轮换：密文头记录key ID/算法版本；新数据新密钥；旧密钥退役前完成重加密与服务端撤销。
- 内存/日志：不把secret写入`UserDefaults`/文件/剪贴板/日志；`os_log`使用隐私标记；崩溃上报脱敏。
- 失败处理：`errSecInteractionNotAllowed`不降级到软件密钥；`errSecAuthFailed`不无限重试；`errSecItemNotFound`区分首次启动与查询错误。
- 测试：锁屏、重启、首次解锁、密码移除、生物识别录入变更、备份恢复、换机、应用卸载重装。

### 7.2 企业侧可操作项

- 把Keychain配置纳入应用安全基线：保护类、ACL、access group、同步/备份策略必须可审计；对高风险应用要求SEP密钥或等价硬件保护。
- 用MDM/应用保护策略强制设备密码、生物识别、最短解锁超时与最低系统版本；对高价值用户限制iCloud备份/同步的范围，但不要把“关闭备份”当成唯一防线。
- 审计企业签名应用的entitlement，尤其是`keychain-access-groups`；限制侧载与共享group；对扩展、键盘、文件提供器单独评估。
- 服务端做令牌绑定与撤销：短有效期、refresh token rotation、设备指纹/attestation、异常使用检测；即使Keychain被读，攻击者也不能长期复用。
- 事件响应：撤销OAuth/会话令牌、轮换服务端密钥、删除设备端item、检查受信设备与iCloud会话；若密码可能泄露，按“类密钥已失陷”处理并擦除设备。

### 7.3 检测信号

Keychain访问的遥测有限，但仍可建立基线：

- 统一日志中`securityd`/`trustd`的异常错误码，尤其是`errSecMissingEntitlement`、`errSecInteractionNotAllowed`、`errSecAuthFailed`的突增。
- 应用在后台/锁屏状态频繁触发生物识别提示，或`LAContext`评估失败率异常；这可能是攻击者诱导认证或探测ACL。
- `SecItemCopyMatching`查询量异常、`kSecMatchLimitAll`使用异常、同一access group被非预期进程访问。
- 服务端：同一refresh token多设备使用、设备绑定不匹配、短时间跨地域访问、token在已知恶意网络段被使用。
- 配置漂移：应用更新后保护类从ThisDeviceOnly降为AfterFirstUnlock、ACL被移除、access group扩大；这类变更应进入CI/CD门禁与运行时审计。

```text
检测分层
  L1 应用：SecItem错误码、认证弹窗、查询频率、配置漂移
  L2 系统：securityd/trustd日志、锁屏/首次解锁状态、MDM合规
  L3 服务端：token绑定、refresh复用、地理/设备异常
  L4 响应：撤销、轮换、删除item、检查备份与受信设备
```

### 7.4 加固优先级

如果只能做三件事：第一，把高价值secret从`AfterFirstUnlock`/`Always`迁到`WhenPasscodeSetThisDeviceOnly`或SEP；第二，把ACL从`.userPresence`/`.biometryAny`收紧到`.biometryCurrentSet` + `.privateKeyUsage`（在UX允许的前提下）；第三，建立密钥轮换与服务端撤销，确保“读到一个token”不等于“长期控制账户”。这三项的收益通常高于再加一层应用内加密。

## 八、结语

iOS的Keychain安全不是“加密数据库”这么简单，而是由entitlement、保护类、keybag、SEP ACL、每行密钥与备份策略共同构成的分层策略。SecItem API把这些策略压缩成几个属性和标志，任何一个配置错误都可能把“硬件保护”降级为“应用进程内的明文”。CryptoKit提供了好用的密码学原语，但它不会自动把密钥放进Secure Enclave；SE密钥提供了不可导出的硬件边界，但它只支持有限算法，且仍受ACL与用户在场约束。

Coruna与DarkSword的公开描述提醒我们：凭证收集不等于Keychain读取，Web会话数据、应用Keychain与SE密钥是三层不同难度的目标；内核读写也不自动等于Keychain明文。防御者应把密钥当作有生命周期的资产，按“生成—存储—使用—轮换—销毁”逐段设计，把保护类、ACL、access group、同步/备份与服务端撤销放在同一张威胁模型里，而不是在出事之后才问“为什么Keychain没有保护我们”。
