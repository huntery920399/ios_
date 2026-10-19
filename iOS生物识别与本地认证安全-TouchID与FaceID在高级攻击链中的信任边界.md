# iOS 生物识别与本地认证安全：Touch ID 与 Face ID 在高级攻击链中的信任边界

> 面向读者：安全研究员、企业安全团队、iOS 应用架构师
> 资料边界：本文只依据 Apple 公开文档、公开安全研究范式，以及任务背景中对 Coruna/DarkSword 的形态描述展开。凡涉及未公开实现、样本行为与组织归属的内容，均标注为“推断”或“公开资料未披露”，不编造 CVE 编号、样本哈希与事件时间线。
> 版本提示：LocalAuthentication、Keychain 与 SEP 的行为随 iOS 版本演进，文中涉及具体系统行为之处，应以目标版本实测与官方文档为准。

## 摘要

Touch ID 与 Face ID 常被误解为“手机上的密码替代品”，但在 iOS 的安全架构中，它们既不是身份凭证，也不是可移植的认证令牌，而是一个由 Secure Enclave（SEP）仲裁的本地“用户在场”信号。应用通过 LocalAuthentication 获得的只是一个布尔结果，真正的秘密始终留在 SEP 与受 ACL 保护的 Keychain 条目之中。这一分层决定了高级攻击链的取舍：攻击者很少去“破解指纹或人脸”，更常见的是绕过应用对布尔结果的信任、诱导用户完成一次真实认证，或在认证完成后读取已解密的内存与文件。

本文从 SEP、模板保护、LAPolicy 语义、Keychain ACL 与注入面出发，讨论生物识别信任边界在越狱、动态注入与内核失陷条件下的实际强度，并以 Coruna/DarkSword 所代表的“远程入口 + 分阶段载荷”与“纯 JavaScript 协同”两种形态为参照，给出风险矩阵、加固清单与检测思路。核心结论是：生物识别本身难以被远程攻破，但它所支撑的“本地授权”极易被应用层的错误信任模型拖垮；把认证结果与具体动作、服务端挑战和 SEP 绑定密钥捆绑，才是可验证的边界。

## 关键词

生物识别；Secure Enclave；LocalAuthentication；Keychain ACL；用户在场；Touch ID；Face ID；Coruna；DarkSword

## 引言

过去十年，移动端的身份认证从“知道什么”快速转向“持有什么”与“生物特征是什么”。iOS 在这一进程中走得比多数平台更彻底：指纹与人脸数据不出安全域，应用只能得到成功或失败；密钥材料可以由 SEP 生成并且不可导出；Keychain 条目可以把“是否允许解封”委托给生物识别。这套设计把生物识别的攻击面压缩到了很窄的范围内，但也制造了一个新的错觉——只要弹出了系统认证框，后续操作就天然可信。

高级攻击链并不需要接受这个前提。Coruna 一类链条以 WebKit 远程入口起步，随后投递分阶段载荷，逐步获取沙箱外能力；DarkSword 一类形态则以纯 JavaScript 协同多个漏洞，尽量减少传统 Native Payload 的落地。两者的共同点在于：它们都优先寻找“信任转换点”，而不是与 SEP 正面碰撞。应用把 `LAContext.evaluatePolicy` 的返回值当作授权凭证、把一次生物识别结果复用于多个动作、把敏感数据放在仅由本地布尔值保护的文件里，这些都会把硬件级的安全边界降级为一行可被 hook 的 `if` 语句。

本文试图回答三个问题。第一，生物识别在 iOS 安全架构中究竟处于什么位置，它保护的是什么、不保护什么。第二，当设备被越狱、进程被注入或内核被攻陷时，LocalAuthentication 与 Keychain ACL 的强度分别如何变化。第三，企业与应用开发者应当如何把“用户在场”从不可验证的本地断言，改造为可被服务端验证的密码学证据。

## 一、生物识别在 iOS 安全架构中的位置

iOS 的安全模型可以粗略划分为三个信任域：应用域、内核域与安全域。应用域包括第三方 App、扩展与 WebContent 进程，受沙箱、代码签名与权限（entitlement）约束；内核域包括 XNU、BSD 层、AppleKeyStore 与文件系统保护；安全域则是 SEP 及其 SEPOS。生物识别跨越了这三个域，但它的“根”只在安全域。

### 1.1 三个信任域与一次认证的完整路径

当应用调用 `LAContext.evaluatePolicy` 时，请求并不会直接抵达传感器。LocalAuthentication 框架把请求交给系统的认证服务，后者协调 SEP 完成匹配，并把布尔结果回传给应用进程。期间，生物模板、匹配分数与传感器原始数据都不会离开安全域。应用能观察到的只有结果、错误码，以及有限的上下文属性（例如 `biometryType`）。

```text
[App / WebContent]
   |  LAContext.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics)
   v
[LocalAuthentication.framework]
   |  XPC / Mach IPC
   v
[securityd / Keychain 子系统]  <---->  [内核 AppleKeyStore]
   |                                        |
   |  match / no-match                      |  keybag 状态、ACL 评估
   v                                        v
[SEP / SEPOS]
   |- biometric template (wrapped, non-exportable)
   |- matching engine (Touch ID / Face ID)
   |- UID key -> class keys -> keybag
   '- returns only success / failure to AP
```

这张图有两个容易被忽略的含义。其一，应用进程位于信任链的最末端，它看到的只是安全域计算出的一个比特，而不是可验证的证明。其二，Keychain ACL 的评估发生在 securityd 与 SEP 协作的路径上，和应用是否“相信”这个布尔值是两个独立问题。理解这一点，是区分“UI 被绕过”和“数据被解密”的关键。

### 1.2 生物识别是本地授权信号，不是身份凭证

密码可以派生密钥、可以作为知识因子被验证、可以在服务端比对哈希；生物特征不行。指纹与人脸在 iOS 中不被当作可比较的 secret，而是被转换为模板后封存在 SEP 内，匹配只在本地发生。因此，生物识别在协议意义上更接近“本地用户在场证明”（local user presence），而不是“身份认证因子”。

这带来一个重要的工程后果：生物识别结果不能离开设备，也不能被服务端独立验证。服务端能验证的，只能是“某个持有设备密钥的客户端，声称自己刚刚完成了本地认证”。如果这个客户端本身被攻陷，声称就失去了意义。后文讨论的所有绕过，本质上都围绕这句话展开。

### 1.3 与口令、Passkey 的信任差异

口令的信任根在服务端（哈希、KDF、风控），Passkey 的信任根在密钥对与源绑定（WebAuthn 的 RP ID、challenge、UV 标志），生物识别的信任根在 SEP 与本地策略。三者经常组合使用：Passkey 在本地解锁时调用生物识别完成 user verification，但 Passkey 的私钥并不等同于生物模板，前者可以被服务端验证，后者永远不能。

这也解释了为什么“生物识别被绕过”与“账号被接管”之间不能直接画等号。若攻击者只是 hook 了 `LAContext`，他得到的是一个虚假的本地 UI 结果；若账号体系还把 Passkey 的 UV 标志、设备绑定密钥与服务端 challenge 绑定在一起，攻击者仍然需要私钥或一次真实的用户认证。反过来，如果应用把生物识别当作唯一的门禁，门后又是一份长期有效的明文令牌，那么 hook 一次就足以完成接管。

## 二、SEP、Touch ID/Face ID 与模板保护

### 2.1 SEP 的硬件位置与 SEPOS

SEP 是 SoC 内的独立协处理器，拥有自己的 ROM、RAM、加密引擎与安全启动链。它运行 SEPOS，公开资料普遍描述其微内核源自 L4 家族。SEP 与应用处理器（AP）之间通过受限的邮箱与共享内存通信，AP 上的软件——包括内核——不能直接读取 SEP 的内部存储。设备启动时，SEP 由 BootROM 验证，随后参与整机的安全启动度量；SEP 发生不可恢复错误时，系统通常会panic并重启，这也从侧面说明它处于信任根附近。

SEP 持有一组设备级密钥，其中 UID key 每台设备唯一且不可被软件读取，GID key 按芯片代际共享。它们不直接暴露给应用，而是用于派生和包装其他密钥，例如文件系统类密钥、Keychain 条目密钥与生物识别模板的包装密钥。Passcode 在开启数据保护时会与 UID key 共同参与密钥派生，使“不知道密码就无法解封”成为硬件约束，而不仅是软件检查。

### 2.2 模板的注册、加密与匹配

Touch ID 在 A7 时代随 iPhone 5s 出现，Face ID 则在 A11 及之后的全面屏机型上引入。两者的传感器差异很大：前者是电容式指纹传感器，后者是包含红外点阵投影、泛光照明与红外相机的 TrueDepth 系统。但它们在安全流程上遵循同一模式：原始数据在传感器与 SEP 之间的受控路径中处理，特征被转换为模板，模板由 SEP 管理的密钥包装后存储，匹配在 SEP 内完成。

Apple 公开的要点包括：生物特征数据不会上传到 iCloud 或 Apple 服务器；模板不会被应用读取；Face ID 会通过神经网络构建面部的数学表示，并支持“替代外貌”以应对造型变化。模板数量也有限制，Touch ID 通常允许注册最多五枚指纹，Face ID 允许一个主外貌加一个替代外貌（具体上限随机型与系统版本可能不同）。

```text
enrollment:
sensor raw data -> secure path -> feature extraction -> template
                                                        |
                                                        v
                                          wrapped by SEP key, stored
                                          outside AP's direct access

authentication:
sensor -> template -> SEP matching engine -> match / no-match
                                             |
                                             +--> AP: Bool only
```

需要强调的是，“模板不出安全域”并不等于“认证不可被滥用”。SEP 只负责回答“这次采集是否匹配已注册模板”，它不回答“这次匹配是否应当授权当前这笔转账”。后者是应用与服务端的责任，也是攻击者最喜欢利用的缝隙。

### 2.3 模板不可导出，但匹配结果可被请求

从攻击者视角看，SEP 是一个黑盒 oracle：你无法取出模板，也无法让 SEP 导出匹配分数，但你可以请求它做一次匹配。只要设备处于可用状态，任何能调用 LocalAuthentication 的前台应用都可以弹出认证框。于是攻击面从“窃取指纹”转移到“请求一次合法匹配”，这也解释了为什么商业间谍软件更偏好钓鱼式诱导、界面伪造与进程注入，而不是生物特征伪造。

在越狱设备上，攻击者甚至可以 hook SpringBoard 或认证 UI 相关进程，让用户看到一个“看起来合理”的弹窗；用户完成真实认证后，SEP 确实返回了成功，但授权的目的已经被替换。这类攻击在密码学上完全合法，在语义上却是彻底的欺骗。生物识别系统本身无法区分“用户想解锁银行 App”与“用户被诱导为攻击者的数据解封买单”。

### 2.4 SEP 密钥与 Keychain ACL 的绑定

Keychain 条目可以通过 `SecAccessControl` 把解封条件声明为“需要生物识别”。在支持 SEP 的设备上，这类条目的密钥材料与 SEP 绑定，评估由 securityd 协同 SEP 完成。常见的访问控制标志包括：

- `kSecAccessControlBiometryAny`：任意已注册生物特征均可解封，录入变更后仍然有效。
- `kSecAccessControlBiometryCurrentSet`：只对当前注册集合有效，新增或删除指纹/人脸后条目失效。
- `kSecAccessControlUserPresence`：生物识别或设备密码均可。
- `kSecAccessControlDevicePasscode`：仅设备密码。
- `kSecAccessControlOr` / `kSecAccessControlAnd`：用于组合约束（可用性随 SDK 版本变化）。

这些标志的意义在于把“是否允许解封”从应用代码下沉到安全域。只要条目使用 `biometryCurrentSet`，攻击者即使成功 hook 了 `LAContext` 并让 UI 返回成功，`SecItemCopyMatching` 仍然会因为缺少真实的 SEP 认证而失败。这个差异是后文风险分级的基础：UI 绕过不等于数据解封。

## 三、LocalAuthentication 策略与降级行为

### 3.1 LAPolicy 的语义差异

`LAPolicy` 不是一个枚举开关，而是一组关于“允许什么回退”的契约。选择哪一项，直接决定了攻击者能否把生物识别降级为设备密码，以及应用是否会把“密码解锁”误当成“生物识别成功”。

| 策略 | 允许的回退 | 典型用途 | 主要风险 |
| --- | --- | --- | --- |
| `deviceOwnerAuthenticationWithBiometrics` | 无（仅生物识别；部分机型仍显示密码入口） | 高风险操作二次确认 | 锁定/未录入时直接失败，可用性差；Face ID 机型的回退行为需实测 |
| `deviceOwnerAuthentication` | 设备密码 | 通用本地门禁 | 密码一旦泄露即可绕过生物识别语义 |
| `deviceOwnerAuthenticationWithWatch` | 配对的 Apple Watch | 戴口罩等场景 | 依赖伴随设备信任，企业环境难以审计 |
| `deviceOwnerAuthenticationWithBiometricsOrWatch` | 生物识别或手表 | 兼顾可用性 | 同上，且策略组合更复杂 |

（手表相关策略自 iOS 17 起提供，具体可用性以目标 SDK 为准。）

从安全角度看，`deviceOwnerAuthentication` 并不是“更宽松的生物识别”，而是“生物识别或密码”的并集。很多应用在文案上写着“请使用 Face ID”，实际却使用了该策略，用户点击“使用密码”后返回 `LAError.userFallback`，应用仍然继续执行敏感操作。这不是系统漏洞，而是策略选择与文案、风控不一致造成的语义漏洞。

### 3.2 LAContext 的生命周期与复用

`LAContext` 是一次认证会话的载体，不是可长期持有的“已认证句柄”。它有几个工程上容易踩坑的属性：

- `canEvaluatePolicy:error:` 只表示当前是否可评估，不表示认证会成功，也不保证评估期间状态不变。
- `evaluatePolicy:localizedReason:reply:` 的 reply 块不在主线程执行，UI 更新必须切回主队列。
- 同一个 context 并发调用可能返回 `LAError.invalidContext`，应按会话串行使用。
- `touchIDAuthenticationAllowableReuseDuration` 允许在短时间内复用 Touch ID 的认证状态，上限为 `LATouchIDAuthenticationMaximumAllowableReuseDuration`（5 分钟）；该机制主要面向 Touch ID，Face ID 的复用行为不同，应以文档与实测为准。
- `interactionNotAllowed` 可以禁止 UI，但这也意味着在需要用户交互的场景中必然失败，不能拿来“静默认证”。

复用窗口是一个被低估的风险点。应用在一次认证后把 context 保存下来，几分钟内继续执行多个敏感操作，表面上每次都会“检查”，实际上并没有再次触发生物识别。若攻击者在这段窗口内接管了应用逻辑，就能以极低成本复用已经解封的密钥。

### 3.3 锁定、重启与录入变更导致的降级

iOS 的生物识别不是永远可用的。以下情况会触发降级或失效：

- 连续多次匹配失败（通常为五次）后进入 `biometryLockout`，必须输入设备密码才能解除。
- 设备重启后、首次解锁前，Keychain 中依赖生物识别的条目不可访问。
- 超过约 48 小时未使用密码解锁，系统可能要求先输入密码。
- 新增或删除指纹/人脸会改变已注册集合，`biometryCurrentSet` 条目随之失效。
- 传感器被遮挡、温度异常、Face ID 超过尝试次数等，都会让评估失败。

这些设计本意是防止“把用户绑在设备前反复尝试”，但也制造了可被社会工程利用的叙事：“系统要求输入密码才能继续”。攻击者可以伪造一个高度逼真的锁定界面，诱导用户在恶意页面或假应用中输入设备密码。一旦密码泄露，生物识别的全部优势都被绕过，因为密码是生物识别的最终回退，也是 keybag 解封的另一半。

### 3.4 biometryType、domainState 与状态判断

应用常用 `LAContext.biometryType` 判断设备支持 Touch ID 还是 Face ID，用 `evaluatedPolicyDomainState` 观察注册集合是否变化。后者在较新系统中已被标记为废弃，且其返回值并不构成安全证明。更稳妥的做法是依赖 Keychain 的 `biometryCurrentSet` 语义：让系统在录入变更时自动使条目失效，而不是让应用自己比较一个不透明的数据块。

还需要注意，`biometryType` 只能说明“这台设备具备什么能力”，不能说明“当前这次认证是否真实发生”。在越狱环境中，这两个属性都可能被 hook；它们适合做 UX 分支，不适合做安全判定。

## 四、应用层滥用与“用户在场”证明绕过

### 4.1 攻击者模型与被攻陷的端点

讨论绕过之前，必须先明确攻击者已经取得了什么。可以粗略分为四档：

1. 远程 Web 内容攻击：攻击者控制网页或 WebView 内容，最多获得 WebContent 进程内的脚本执行能力。
2. 应用内注入：通过越狱插件、动态库注入或调试接口，取得目标应用进程的用户态代码执行能力。
3. 系统级用户态控制：通过沙箱逃逸与内核漏洞获得 root 或内核读写，能够注入系统进程、读取文件与内存。
4. 引导链或固件级控制：破坏安全启动、持久化植入引导组件，或取得 SEP 之外更深层的能力。

生物识别在这四档中的表现完全不同。第 1 档几乎无法触及 LocalAuthentication；第 2 档可以伪造 UI 结果，但通常无法直接解封 SEP 绑定的条目；第 3 档可以读取认证后的内存与文件，也可以替换应用逻辑；第 4 档则需要重新评估整个信任模型，公开资料对 Coruna/DarkSword 是否达到这一层级没有披露。

### 4.2 常见注入点与 hook 目标

在越狱或动态注入环境中，攻击者常用的落点包括：

- Objective-C 方法交换：`-[LAContext evaluatePolicy:localizedReason:reply:]`、`-[LAContext canEvaluatePolicy:error:]`，把 reply 的 `success` 直接改为 `true`。
- C 函数 inline hook：`SecAccessControlCreateWithFlags`、`SecItemCopyMatching`、`SecKeyCreateSignature`，拦截参数或返回值。
- Swift 虚表与 witness table 替换：针对纯 Swift 封装层，绕过对 Objective-C 方法的依赖。
- UI 层伪造：hook SpringBoard 或认证提示相关进程，显示与系统一致的弹窗，收集密码或诱导点击。
- 调试与重签名：通过 `get-task-allow`、调试器附加、企业证书重签，把应用装到可控设备上再分析。

在 arm64e 设备上，inline hook 需要处理指针认证（PAC），门槛高于早期的 Objective-C swizzling；但一旦攻击者已经取得内核读写，PAC 与代码签名都不再构成实质阻碍。此时应用层的任何“反 hook”都只能提高成本，不能提供证明。

### 4.3 把布尔值当授权：最普遍的信任错误

最典型的错误模式如下：应用调用 `evaluatePolicy`，在 reply 中收到 `success == true` 后，直接把一个本地布尔变量置为“已认证”，后续所有敏感操作都检查这个变量。攻击者只需 hook 一次 reply，就能让整个会话进入已认证状态。更糟糕的是，有些应用把该布尔值写入 `UserDefaults`，让“已认证”跨启动持久化。

```text
正常路径:
App -> LAContext -> securityd -> SEP match -> success
    -> Keychain ACL unwrap -> plaintext token -> API call

注入路径:
App -> [hook evaluatePolicy] -> reply(true)  (SEP 未参与)
    -> 本地 bool = true
    -> 若数据仅由 bool 保护: 直接读取
    -> 若数据由 biometryCurrentSet 保护: SecItemCopyMatching -> errSecAuthFailed
```

这张图给出了两条完全不同的结论。对于“仅由布尔值保护”的数据，hook 即失守；对于“由 SEP ACL 保护”的数据，hook 只欺骗了 UI，数据仍然锁在安全域里。应用的安全等级，取决于它把秘密放在哪一侧。

### 4.4 Keychain ACL 在失陷端点上的实际强度

`biometryCurrentSet` 条目并不是绝对不可攻破，但它的攻击面与 UI 绕过完全不同。攻击者可行的路径包括：

- 等待或诱导用户完成一次真实认证，然后在认证有效期内读取条目。
- 在应用完成解封后读取其内存，直接获取明文令牌。
- 替换应用二进制或注入 dylib，让应用自己把解密后的数据发送到攻击者服务器。
- 利用内核读写直接访问文件系统与 keybag 相关结构，但这通常仍受 SEP 保护的类密钥约束。

公开研究中对“完全软件模拟 SEP 认证”的可行性存在争议，且高度依赖具体芯片与系统版本。可以确定的是：在未取得 SEP 密钥、也未获得一次真实认证的前提下，单纯 hook `LAContext` 不足以解封 `biometryCurrentSet` 条目。这一结论应作为设计假设，而不是对某次攻击的归因。

### 4.5 混淆代理：让用户为攻击者完成认证

比 hook 更优雅的方式是“混淆代理”（confused deputy）。攻击者不伪造成功，而是让系统弹出一个真实的认证框，理由写得合情合理，例如“验证身份以继续同步”“解锁安全存储以恢复备份”。用户完成 Face ID 后，SEP 返回真实成功，攻击者随即在自己的上下文中使用这次授权，或诱导应用把敏感数据写入攻击者可控的位置。

这类攻击无法靠“检测越狱”根治，因为认证确实发生了，密码学链条也是完整的。唯一的缓解是把授权语义绑定到具体动作：认证框的文案、被签名的挑战、交易金额与收款方、一次性 nonce，都应当由服务端生成并被 SEP 密钥签名。用户看到的内容与签名内容必须一致，服务端必须验证这种一致性。

## 五、与 Coruna/DarkSword 凭证窃取链的关系推断

### 5.1 两种公开形态的差异

按任务背景与公开分析中的通行描述，Coruna 以 WebKit 远程入口加分阶段载荷为特征：先获得脚本执行，再逐步投递加载器与后续模块，目标是把能力从 WebContent 推进到更高权限的进程。DarkSword 则以纯 JavaScript 协同多个漏洞、较少依赖传统 Native Payload 为特征：攻击逻辑尽量停留在脚本层，通过多个缺陷的组合完成信息收集、权限推进与数据回传。

这两种形态对生物识别的威胁并不相同。Coruna 的分阶段载荷如果最终获得用户态注入或系统级控制，就具备了“在认证之后读取明文”的能力；DarkSword 的纯脚本形态若始终停留在 WebContent 沙箱内，则很难直接触碰 LocalAuthentication，但其窃取目标可能转向 Web 会话、Cookie、自动填充数据与页面内的凭据输入。

### 5.2 凭证窃取链的可能落点（推断）

以下映射属于基于公开攻击范式的推断，不代表已披露的样本行为：

- 阶段一，入口与侦察：通过 WebKit 漏洞获得脚本执行，收集设备型号、系统版本、语言、已安装应用的可探测特征，判断是否存在可用的后续漏洞。
- 阶段二，沙箱推进：利用沙箱逃逸或 IPC 缺陷，从 WebContent 进入更具权限的进程，获取文件读取、进程枚举或注入能力。
- 阶段三，凭证收集：扫描应用容器、Keychain 中可访问的条目、`UserDefaults`、日志与备份文件；hook 目标应用的登录与令牌刷新逻辑；读取认证后的内存。
- 阶段四，保活与外传：通过后台任务、推送唤醒、注入的系统进程或重新感染维持存在，把数据编码后经 HTTPS、WebSocket 或云存储外传。

在这条链上，生物识别通常只在两个位置出现：一是应用启动或敏感操作时的本地门禁，二是 Keychain 条目的解封条件。对第一处，攻击者用 hook 或界面伪造即可；对第二处，攻击者更倾向于等待用户认证后读取内存，而不是尝试破解 SEP。换言之，生物识别提高了“静默窃取”的成本，但没有改变“端点被控制后秘密终将暴露”的事实。

### 5.3 为什么生物识别通常不是阻断点

生物识别的设计目标是防止他人在用户不知情时解锁设备或授权支付，而不是防止恶意软件在用户已经解锁的设备上活动。一旦设备处于“已解锁、已认证”的状态，应用内存中的令牌、Cookie、明文缓存对拥有相应权限的攻击者就是可读的。生物识别只保护“解封动作”，不保护“解封之后”。

此外，企业应用常见的“一次认证、长期有效”模式进一步削弱了它的价值。用户早上用 Face ID 登录，会话令牌有效期长达数周，期间不再触发任何生物识别。攻击者只要在任意时刻取得该令牌，就能在服务端冒充用户，直到令牌过期或风控触发。生物识别在这个模型里只参与了第一分钟。

### 5.4 公开资料未披露的部分

截至本文写作时，Coruna 与 DarkSword 的完整战术、工具链与归属仍有大量未公开信息。本文不推测其是否使用特定 SEP 漏洞、是否具备固件级持久化、是否针对特定银行或加密货币应用，也不给出未经证实的 CVE 编号。可以讨论的是能力类别与防御原则：远程入口、沙箱推进、用户态注入、凭证收集、保活外传，这些环节的防御并不依赖于对某个组织的精确归因。

## 六、风险评估矩阵

下表把常见场景按“攻击前提、直接影响、可能性、检测难度”四个维度排列。可能性是定性判断，不是统计结论；它假设攻击者已经具备相应前提，而不是对某个真实事件的评估。

| 风险场景 | 攻击前提 | 直接影响 | 可能性 | 检测难度 |
| --- | --- | --- | --- | --- |
| 仅以 `LAContext` 布尔值作为授权 | 应用内注入或越狱 | 本地功能被解锁，受该布尔值保护的明文可读 | 高 | 中 |
| Keychain 条目使用 `biometryAny` | 越狱 + 一次真实认证 | 录入变更后仍可解封，攻击窗口更长 | 中 | 中 |
| Keychain 条目使用 `biometryCurrentSet` | 无 SEP 认证 | 直接读取失败，需诱导认证或读内存 | 低 | 高 |
| 使用 `deviceOwnerAuthentication` 作为高风险门禁 | 设备密码泄露 | 生物识别被降级为密码，语义被绕过 | 高 | 低 |
| 认证结果跨会话复用（复用窗口） | 应用内注入 | 无需再次认证即可执行敏感操作 | 中 | 中 |
| 认证 UI 被伪造/混淆代理 | 系统进程注入 | 用户为攻击者完成真实认证 | 中 | 高 |
| 认证后内存与文件被读取 | 内核读写或系统级注入 | 令牌、Cookie、明文缓存泄露 | 中 | 高 |
| Passkey 的 UV 标志被伪造 | 端点被完全控制 | 服务端可能接受虚假的用户验证 | 低至中 | 高 |
| 生物模板被直接窃取 | 需要 SEP 级缺陷 | 长期不可撤销的身份风险 | 极低 | 极高 |
| 固件级持久化 | 引导链缺陷 | 重装系统也可能无法清除 | 极低（公开证据有限） | 极高 |

矩阵传达的核心信息是：风险最高的行几乎都与“应用如何信任认证结果”有关，而不是与“SEP 是否足够强”有关。把资源投入到 SEP 破解防护，收益远低于把授权语义绑定到服务端挑战与具体动作。

## 七、加固建议

### 7.1 正确选择 LAPolicy

高风险操作应使用 `deviceOwnerAuthenticationWithBiometrics`，并明确处理 `biometryNotAvailable`、`biometryNotEnrolled`、`biometryLockout` 与 `userFallback`。如果业务必须允许密码回退，应使用 `deviceOwnerAuthentication`，但在服务端把“本次是密码回退”记为降低的保证等级：缩短会话、增加风控、限制可执行的操作，而不是把回退成功等同于生物识别成功。

不要用 `localizedFallbackTitle = ""` 来“假装”没有密码回退。该设置在不同机型与系统版本上的表现并不一致，尤其在 Face ID 设备上，系统仍可能提供密码入口。真正的控制点在服务端策略，而不是按钮文案。

### 7.2 用 Keychain ACL 把秘密锁在 SEP 后面

高价值条目应使用 `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` 与 `.biometryCurrentSet`，禁止 iCloud 同步，禁止在设备间迁移。这样即使应用层被 hook，攻击者也需要一次真实的 SEP 认证才能解封。对于纯本地秘密（例如数据库密钥、刷新令牌），不要退化为“认证后写入 UserDefaults”或“认证后写入普通文件”。

```swift
// 受生物识别保护的 Keychain 条目（示意）
let acl = SecAccessControlCreateWithFlags(
    nil,
    kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
    .biometryCurrentSet,
    nil
)!

let attrs: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: "com.example.vault",
    kSecAttrAccount as String: "refresh_token",
    kSecAttrAccessControl as String: acl,
    kSecUseDataProtectionKeychain as String: true
]
SecItemAdd(attrs as CFDictionary, nil)
```

读取时通过 `kSecUseAuthenticationContext` 传入一个专用的 `LAContext`，让系统在查询阶段触发生物识别，而不是先调用 `evaluatePolicy` 再把结果当作授权。这样解封动作与数据访问是同一次安全域操作，应用无法用一次认证去解封多个不相关的条目。

### 7.3 SE 绑定密钥与服务端挑战

对转账、改密、导出密钥等高价值动作，应生成 SEP 绑定的 P-256 密钥（`kSecAttrTokenIDSecureEnclave`），私钥不可导出，签名操作受 ACL 约束。服务端下发一次性挑战，挑战中应包含动作类型、金额、收款方、时间戳与随机数；客户端在生物识别通过后调用 `SecKeyCreateSignature`，服务端验证签名、挑战与业务参数的一致性。

```text
server: nonce, action=transfer, amount, payee, expiry
   |
   v
app: display exactly the signed fields
   |
   v
LAContext (biometryCurrentSet) -> SEP unwrap -> SecKeyCreateSignature
   |
   v
server: verify signature + nonce freshness + fields match + device posture
```

这套流程的价值在于：即使攻击者 hook 了 `LAContext`，没有 SEP 私钥就无法生成有效签名；即使攻击者诱导用户完成认证，签名内容也必须与用户看到的內容一致，否则服务端拒绝。生物识别从“本地布尔值”变成了“参与密码学操作的解锁条件”。

### 7.4 App Attest、DeviceCheck 与设备姿态

App Attest 可以为应用实例生成受 SEP 保护的 attestation key，服务端通过 Apple 的根证书验证应用完整性；DeviceCheck 提供每设备两位状态，适合标记“曾被判定风险”的设备。两者都不是万能的：App Attest 证明的是“运行的是正版应用”，不证明“设备未被越狱”，也不证明“用户本人在场”。它们应与生物识别、服务端风控、MDM 合规状态组合使用。

### 7.5 会话、存储与工程实践

- 会话令牌短寿命、可撤销、绑定设备密钥；刷新令牌放入受 ACL 保护的 Keychain，而不是 `UserDefaults`。
- 敏感数据不要以“认证后可读”的明文形式长期落盘；使用 `NSFileProtectionComplete` 或更严格的保护类，并在内存中使用后及时清零。
- 不要用生物识别保护“可被重放”的静态口令；每次授权都应绑定新的挑战。
- 对 `LAError` 做细分处理，不要把所有失败都当成“用户取消”而静默降级。
- 在发布构建中移除调试符号与测试入口，避免 `get-task-allow`，使用独立的企业签名与最小权限 entitlements。
- 对高风险管理设备启用 Lockdown Mode 与“失窃设备保护”（iOS 17.3 起），降低密码回退与设备被物理控制后的风险。

## 八、检测思路

### 8.1 端侧检测

端侧检测的目标不是“证明设备安全”，而是收集可用于风险决策的信号。可观测项包括：

- `LAContext` 的错误分布：短时间大量 `biometryLockout`、`notInteractive`、`userFallback`，可能意味着自动化探测或界面伪造。
- `biometryType` 与已注册集合的异常变化；`evaluatedPolicyDomainState` 在短时间内的漂移。
- Keychain 查询失败的集中出现（`errSecAuthFailed`、`errSecInteractionNotAllowed`），可能意味着注入后的批量读取尝试。
- 进程环境异常：非预期的动态库、异常的父进程、调试器附着、代码签名校验失败、`/var/jb` 等越狱路径存在。
- 认证 UI 与实际业务动作不匹配：用户在认证后没有看到预期的业务页面，或认证频率异常升高。

这些信号都容易被有能力的攻击者规避，因此只能作为纵深防御的一层。对高风险操作，端侧检测失败时应选择“拒绝并上报”，而不是“静默继续”。

### 8.2 服务端检测

服务端应把“本地认证”视为一个需要交叉验证的声明，而不是事实。可用的检测包括：

- 设备绑定：同一账号的令牌是否突然来自新的设备密钥或新的 attestation 实例。
- 行为基线：认证成功后的操作序列是否与历史模式一致，是否出现批量导出、异常收款方、短时间多地登录。
- 挑战一致性：签名中的动作、金额、时间戳是否与服务端下发的挑战完全匹配，nonce 是否被重复使用。
- 降级信号：客户端上报的认证类型是生物识别还是密码回退；回退后的高风险操作应触发额外验证。
- Passkey 的 UV 标志与源绑定：检查 RP ID、origin、challenge 与 UV，避免仅凭“已认证”放行。

### 8.3 组织侧检测

企业应把 iOS 设备纳入统一的合规与威胁狩猎流程：MDM 强制最低系统版本、禁止未知描述文件、要求设备加密与锁屏密码、对高风险管理岗位启用 Lockdown Mode；用 DNS 与出口流量日志识别异常回连；定期审查设备上的配置描述文件与企业管理状态；对“生物识别失败率突然升高”“设备出现越狱特征”“Keychain 访问异常”等事件建立告警与处置剧本。

## 九、结语

生物识别在 iOS 上是一项扎实的硬件安全能力：模板不出安全域，密钥不可导出，解封可以由 SEP 仲裁。但它的保护范围被严格限定在“本地解封动作”，而不是“身份本身”，更不是“解封之后的会话”。高级攻击链不需要攻破 SEP，它们只需要让应用相信一个被伪造的布尔值，或者让用户在不知情中为攻击者完成一次真实认证。

对防御者而言，正确的方向不是寻找“绝对安全的认证方式”，而是把信任从本地断言迁移到可验证的证据：SEP 绑定密钥、一次性挑战、动作绑定签名、服务端风控与设备姿态的组合。Coruna 与 DarkSword 所代表的两类形态提醒我们，远程入口与纯脚本协同都可以绕过应用层的门禁，但无法凭空生成 SEP 私钥。把秘密放在 SEP 后面，把授权绑定到具体动作，把检测做成多层信号，才是这条信任边界上真正可操作的加固路径。
