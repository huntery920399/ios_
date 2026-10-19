# iOS 后台执行与持久化机制分析：从 BackgroundTasks 到系统守护进程的驻留攻防

> 面向读者：安全研究员、企业安全团队、iOS 应用架构师
> 资料边界：本文依据 Apple 公开文档、公开越狱与恶意软件研究范式，以及任务背景中对 Coruna/DarkSword 的形态描述展开。凡涉及未公开实现、具体样本行为与组织归属的内容，均标注为“推断”或“公开资料未披露”，不编造 CVE 编号、样本哈希与事件时间线。
> 版本提示：后台调度策略、launchd 行为与越狱工具链随版本变化，文中涉及具体系统行为之处，应以目标版本实测与官方文档为准。

## 摘要

iOS 的后台执行模型是一套以省电、隐私和用户体验为优先的受控调度系统：应用不能自行决定长期驻留，只能向系统申请有限的执行机会；真正决定何时唤醒、运行多久的，是 launchd、RunningBoard 与 Duet Activity Scheduler 等系统组件。越狱打破了这一约束，LaunchDaemons/LaunchAgents 成为持久的用户态入口，动态库注入与内核补丁进一步把“驻留”从应用容器扩展到系统进程。

本文沿着三条线索展开。第一条是官方后台机制：BackgroundTasks、后台 URLSession、静默推送、后台音频/定位/蓝牙，它们各自的唤醒源、时间预算与滥用检测点。第二条是越狱环境的持久化：launchd 的 plist 语义、rootful 与 rootless 的路径差异、注入链与守护进程组合。第三条是攻击链视角：Coruna 的分阶段载荷与 DarkSword 的纯 JavaScript 协同分别需要什么样的驻留能力，哪些环节只能依赖重新感染，哪些环节可能落到系统守护进程。

核心结论是：在未越狱的 iOS 上，真正意义上的“开机自启守护进程”极难实现，高级攻击链更依赖重新感染、系统进程注入与用户辅助的配置持久化；在越狱设备上，持久化成本急剧下降，但可见性也显著上升。防御的重点不是寻找某个“持久化开关”，而是建立从进程、launchd、电源、网络到账号行为的联合检测，并把高风险设备的恢复流程预设为“擦除 + 重装 + 凭证轮换”。

## 关键词

BackgroundTasks；BGTaskScheduler；launchd；LaunchDaemon；持久化；后台执行；Coruna；DarkSword

## 引言

移动端的“持久化”与桌面端有本质区别。桌面系统允许用户安装常驻服务，登录项、cron、systemd 都是公开且稳定的机制；iOS 则把常驻能力收归系统，第三方应用只能使用被严格审计的后台模式。这个设计极大地压缩了恶意软件的生存空间，也让攻击链的工程重心发生转移：与其在设备上安装一个守护进程，不如让用户再次打开恶意页面，或者把载荷注入一个本来就会长期运行的系统进程。

Coruna 与 DarkSword 代表了两条不同的工程路线。前者以 WebKit 远程入口起步，随后投递分阶段载荷，通常需要在获得更高权限后解决“如何持续存在”的问题；后者以纯 JavaScript 协同多个漏洞，尽量减少 Native Payload 的落地，其“驻留”更可能表现为会话内潜伏与重新投递，而不是系统级常驻。两条路线都必须面对同一组约束：代码签名、沙箱、launchd 的注册权限，以及用户重启设备后的一切归零。

本文讨论的“后台执行”既包括 Apple 公开的 API，也包括越狱环境下的 launchd 机制。前者是每一个 App 都要使用的合法能力，也是攻击者可以滥用的灰色地带；后者是高级攻击链在取得 root 之后才可能触及的领域。把两者放在同一张图上，才能理解为什么“后台刷新”与“开机自启”之间隔着一条巨大的权限鸿沟。

## 一、iOS 后台执行模型演进

### 1.1 从伪多任务到受控调度

早期的 iPhone 并不支持真正的第三方后台执行。iOS 4 引入快速应用切换与有限的“后台化”，iOS 7 引入后台获取（Background Fetch），iOS 9 增加后台 URLSession 与更丰富的推送唤醒，iOS 13 用 BackgroundTasks 框架取代了逐渐失控的后台模式，把刷新与处理任务纳入统一的调度器。此后，Apple 持续收紧 VoIP 推送、后台定位与静默推送的滥用空间，并在较新版本中引入面向用户显式发起的连续处理任务（例如 iOS 26 的 `BGContinuedProcessingTask`，具体可用性以官方文档为准）。

这条演进路线有一个清晰的方向：把“应用想什么时候运行”改为“系统认为什么时候应该运行”。应用提供任务标识、最早开始时间与资源需求，系统根据设备电量、热状态、网络、用户使用习惯与隐私预算决定是否执行。开发者能做的只是“申请”，不是“命令”。

### 1.2 进程生命周期与状态机

一个 iOS 应用通常经历 not running、inactive、active、background、suspended 与 terminated 等状态。进入后台后，应用有很短的时间完成收尾；随后系统可能将其挂起，内存紧张时由 jetsam 终止。被挂起的应用并没有“死”，它保留地址空间，但不执行代码；只有收到特定事件（推送、URLSession 回调、后台任务、定位事件、蓝牙事件）时，系统才会把它唤醒到后台运行状态。

需要区分“崩溃”与“正常终止”。主线程长时间无响应会触发 watchdog，日志中常见 `0x8badf00d`；内存超限会被 jetsam 终止；后台任务超时未结束也会被系统强杀。MetricKit 的 `MXAppExitMetric` 会把前台/后台退出按原因分类（正常退出、watchdog、内存限制、CPU 限制等），适合在版本发布后观察后台稳定性，而不是用于实时检测攻击。

```text
user / push / timer / location event
              |
              v
   [BackgroundTasks framework] --register/submit--> [DAS scheduler (dasd)]
              |                                            |
              | launch handler                             | budget, battery,
              v                                            | thermal, usage
      [App process] <--- launch --- [runningboardd] <--- [launchd (PID 1)]
              |
              |- beginBackgroundTask      (~30 s)
              |- BGAppRefreshTask         (~30 s)
              '- BGProcessingTask         (minutes, power/network hints)
```

RunningBoard 负责应用进程的生命周期与断言管理，launchd 负责系统与用户会话的引导，DAS（Duet Activity Scheduler）根据策略决定后台活动的执行时机。三者共同构成了“谁在什么时候可以运行”的仲裁结构。理解这一点，就能明白为什么单纯调用 API 并不能保证任务执行，也能明白为什么攻击者一旦取得 root，最想做的第一件事就是直接与 launchd 对话。

### 1.3 三个硬约束：电量、热与用户习惯

后台执行不是免费的。系统会为每个应用维护后台预算，低电量模式、过热、弱网、长时间未使用都会降低执行概率。后台任务被调用时，应用必须尽快完成工作并在 `expirationHandler` 中调用 `setTaskCompleted`；超时未完成会被系统终止，甚至影响后续调度配额。对于攻击者而言，这些约束同样有效：一个频繁唤醒的植入进程会显著增加耗电与网络活动，反而提高被发现的概率。

## 二、BackgroundTasks/BGTaskScheduler 与系统调度

### 2.1 注册、提交与标识符

使用 BackgroundTasks 的第一步是在应用完成启动前注册任务标识符。注册必须发生在 `application(_:didFinishLaunchingWithOptions:)` 返回之前，否则系统会拒绝后续提交。标识符需要同时出现在 Info.plist 的 `BGTaskSchedulerPermittedIdentifiers` 中，并按任务类型声明对应的后台模式（`fetch` 或 `processing`）。

```xml
<key>BGTaskSchedulerPermittedIdentifiers</key>
<array>
  <string>com.example.sync.refresh</string>
</array>
<key>UIBackgroundModes</key>
<array>
  <string>fetch</string>
</array>
```

```swift
BGTaskScheduler.shared.register(
    forTaskWithIdentifier: "com.example.sync.refresh",
    using: nil
) { task in
    guard let refresh = task as? BGAppRefreshTask else { return }
    scheduleNextRefresh()
    refresh.expirationHandler = {
        refresh.setTaskCompleted(success: false)
    }
    Task {
        let ok = await syncOnce()
        refresh.setTaskCompleted(success: ok)
    }
}
```

注册之后，应用通过 `BGAppRefreshTaskRequest` 或 `BGProcessingTaskRequest` 提交请求，并设置 `earliestBeginDate`。后者只是“最早不早于”，不是“保证在此刻执行”。`BGProcessingTaskRequest` 还可以声明 `requiresNetworkConnectivity` 与 `requiresExternalPower`，系统会据此把任务安排到更合适的窗口。

### 2.2 BGAppRefreshTask 与 BGProcessingTask 的差异

`BGAppRefreshTask` 面向轻量、快速的数据刷新，典型运行时间约 30 秒，适合拉取增量、更新缓存、上报少量事件。它的调度频率与用户打开应用的频率相关，系统会学习使用习惯，对长期不用的应用减少甚至停止刷新。

`BGProcessingTask` 面向耗时更长的维护工作，例如数据库清理、模型更新、批量上传。它可以运行数分钟，但是否执行、运行多久仍由系统决定；声明“需要外接电源”或“需要网络”会进一步降低被调度的概率。两类任务都不是持久化机制：应用被用户强制退出后，系统通常不会为其启动后台任务，直到用户再次手动打开应用。

### 2.3 过期处理、错误码与常见误用

`BGTaskScheduler` 的提交可能失败，常见错误包括未授权（`notPermitted`）、待处理请求过多（`tooManyPendingTaskRequests`）与调度器不可用（`unavailable`）。工程上常见的误用有：

- 在 `expirationHandler` 中只做日志，不调用 `setTaskCompleted`，导致任务被系统强杀。
- 在任务回调中执行同步网络请求，阻塞过期处理。
- 每次启动都提交大量请求，触发配额限制。
- 把标识符写死在代码里却忘记写入 Info.plist，导致注册失败。
- 依赖后台刷新做关键同步，用户长期不打开应用时数据严重滞后。

调试时可以在 LLDB 中调用 `_simulateLaunchForTaskWithIdentifier:` 触发任务，但这是私有调试接口，只能用于开发环境，不能作为生产逻辑的一部分。

### 2.4 后台 URLSession 与会话级续命

后台 URLSession 是少数能在应用被挂起甚至终止后继续工作的机制。使用 `URLSessionConfiguration.background(withIdentifier:)` 创建的会话由系统守护进程 `nsurlsessiond` 托管，上传下载不依赖应用进程存活；任务完成后，系统可以在后台重新启动应用并调用 `handleEventsForBackgroundURLSession`。这为攻击者提供了一个有价值的特性：一个待完成的后台传输可以成为“让应用再次运行”的理由。

防御上，应限制后台会话的数量与用途，避免把长期轮询、心跳或数据外传伪装成用户可见的下载任务；对 `handleEventsForBackgroundURLSession` 中恢复的会话做完整性校验，避免攻击者通过替换缓存文件或注入会话配置来劫持传输。

`beginBackgroundTask` 则用于应用刚进入后台时的短时收尾：调用后获得一个 `UIBackgroundTaskIdentifier`，必须在过期回调或工作完成后调用 `endBackgroundTask`，否则系统会终止应用。`ProcessInfo.performExpiringActivity` 提供类似能力，但同样只有有限时间。它们适合保存状态、关闭文件、提交最后一批日志，不适合承载长连接或周期性任务；把心跳放进 `beginBackgroundTask`，只会让应用在每次切后台时被系统更快地清理。

## 三、推送唤醒、后台音频/定位/蓝牙

### 3.1 静默推送与 APNs 的边界

静默推送通过 APNs 负载中的 `content-available: 1` 唤醒应用，配合 `apns-push-type: background` 与较低的优先级使用。它适合通知应用“有新数据可拉取”，不适合承载关键指令：系统会根据电量、网络与用户习惯进行节流，推送可能延迟、合并甚至丢弃。应用被唤醒后通常只有几十秒时间，且必须调用 `fetchCompletionHandler` 结束。

从攻击链视角看，静默推送是一条低带宽、高可达的控制通道，但它依赖 APNs 与有效的设备令牌，且不能保证实时性。更重要的是，推送本身不能安装代码，只能触发已经存在的逻辑；如果应用没有相应的处理路径，推送就只是一条通知。

### 3.2 PushKit 与 VoIP 推送的收紧

PushKit 最初为 VoIP 应用提供高优先级唤醒，允许应用在收到推送后立即建立连接。iOS 13 之后，VoIP 推送必须与 CallKit 或 `INStartCallIntent` 绑定：收到推送后若未报告来电，系统会终止应用并可能撤销其推送权限。这一变化大幅压缩了“用 VoIP 推送保活”的空间，也让 PushKit 不再是通用的后台执行通道。

### 3.3 后台音频：最古老的保活手法

声明 `audio` 后台模式并使用 `AVAudioSession` 的播放类别，应用可以在后台持续播放音频。历史上，播放静音音频是常见的保活手法；随着审核规则与系统行为的收紧，这种做法越来越难以通过审核，也容易被电池与音频会话监控发现。对攻击者而言，后台音频的优势是稳定，劣势是极其显眼：控制中心的音频指示、电池用量与音频会话日志都会留下痕迹。

### 3.4 后台定位与蓝牙：事件驱动的唤醒

后台定位通过 `CLLocationManager` 的 `allowsBackgroundLocationUpdates`、显著位置变化监控与区域监控实现。应用需要声明 `location` 后台模式并获得“始终允许”授权，系统会在状态栏显示定位指示。定位事件可以唤醒被挂起的应用，但频率与精度受系统控制，长期高频定位会显著耗电。

蓝牙外设在声明 `bluetooth-central` 后可以使用状态保存与恢复：通过 `CBCentralManagerOptionRestoreIdentifierKey` 创建管理器，系统在蓝牙事件到达时重启应用并调用 `willRestoreState`。`external-accessory` 与 `nearby-interaction` 也属于事件驱动的后台模式，但适用场景更窄。它们共同的特点是“由外部事件触发”，而不是应用自行决定运行。

| 机制 | 唤醒源 | 典型时长 | 关键约束 | 跨重启 | 滥用检测点 |
| --- | --- | --- | --- | --- | --- |
| `BGAppRefreshTask` | 系统调度 | 约 30 秒 | 需注册标识符与 `fetch` 模式，受预算限制 | 否 | 调度频率、耗电、后台崩溃 |
| `BGProcessingTask` | 系统调度 | 数分钟 | 需 `processing` 模式，可要求充电/网络 | 否 | 长任务、CPU 与热异常 |
| `beginBackgroundTask` | 应用进入后台 | 约 30 秒 | 必须调用 `endBackgroundTask` | 否 | 超时未结束、频繁申请 |
| 后台 URLSession | 系统守护进程 | 分钟到小时 | 由 `nsurlsessiond` 托管 | 可重新启动应用 | 异常大流量、非用户发起的传输 |
| 静默推送 | APNs | 数十秒 | 节流、优先级低、不保证送达 | 否 | 高频推送、唤醒后短连接 |
| VoIP 推送 | APNs/PushKit | 通话建立 | 必须报告 CallKit 来电 | 否 | 未报告来电、频繁唤醒 |
| 后台音频 | 音频会话 | 持续 | 需 `audio` 模式，审核严格 | 否 | 静音播放、音频会话常驻 |
| 后台定位 | 位置事件 | 持续/事件 | 需 `location` 模式与授权 | 否 | 蓝色指示、异常定位频率 |
| 蓝牙中央 | 蓝牙事件 | 事件 | 需 `bluetooth-central` 与状态恢复 | 可恢复 | 长期扫描、异常外设连接 |

这张表的关键结论是：所有官方机制都只能在“应用仍然被系统认可”的前提下工作，没有任何一项能让第三方应用在未越狱设备上获得开机自启的守护进程。所谓“保活”，本质上是在系统允许的窗口内延长运行时间，而不是获得持久化。

## 四、越狱环境下的 LaunchDaemons/LaunchAgents

### 4.1 launchd 与 plist 的关键字段

越狱之后，攻击者或插件开发者可以直接向 launchd 注册守护进程。iOS 的 launchd 是 PID 1，负责引导系统与用户会话；它读取 `/System/Library/LaunchDaemons`、`/System/Library/LaunchAgents` 以及越狱环境新增的 `/Library/LaunchDaemons`、`/Library/LaunchAgents`。LaunchDaemon 运行在系统上下文，通常以 root 身份执行，不能直接访问图形界面；LaunchAgent 运行在用户会话，适合需要与 SpringBoard 交互的组件。

一个典型的守护进程 plist 包含以下字段：

```xml
<key>Label</key>
<string>com.example.agent</string>
<key>ProgramArguments</key>
<array>
  <string>/usr/local/bin/agent</string>
</array>
<key>RunAtLoad</key>
<true/>
<key>KeepAlive</key>
<dict>
  <key>SuccessfulExit</key>
  <false/>
</dict>
<key>ThrottleInterval</key>
<integer>30</integer>
```

`RunAtLoad` 让任务在加载时立即运行；`KeepAlive` 让 launchd 在进程退出后按条件重启；`StartInterval` 与 `StartCalendarInterval` 提供周期性触发；`WatchPaths` 可以在文件变化时启动任务；`MachServices` 允许其他进程通过 XPC 查找服务。`ThrottleInterval` 用于限制重启频率，避免崩溃循环拖垮系统。iOS 的 launchd 支持的键是 macOS 的子集，具体行为应以目标版本为准。

### 4.2 rootful 与 rootless 的路径差异

传统 rootful 越狱把文件写入 `/Library`、`/usr` 等系统路径，并通过 remount 或快照机制绕过签名系统卷（SSV）。rootless 越狱则把前缀映射到 `/var/jb`，守护进程 plist 位于 `/var/jb/Library/LaunchDaemons`，动态库位于 `/var/jb/usr/lib`，包管理器数据库位于 `/var/jb/var/lib/dpkg/status`。两种形态的检测点不同：rootful 更接近系统原生路径，隐蔽性略好；rootless 的 `/var/jb` 前缀本身就是强特征。

在 iOS 15 之后，系统卷受到 SSV 保护，直接修改 `/System/Library/LaunchDaemons` 变得更加困难；越狱工具通常通过引导脚本、bind mount 或早期启动阶段的补丁来注册自己的守护进程。具体实现随工具与版本差异很大，公开资料也未覆盖所有细节。

### 4.3 注入链：从 amfid 到 SpringBoard

要在系统进程中长期驻留，仅有一个守护进程还不够，还需要把代码注入到“本来就会长期运行”的进程。常见路径包括：

- 修补 `amfid`（Apple Mobile File Integrity）以放宽代码签名校验，或向 trust cache 注入条目，让未签名二进制得以执行。
- 通过 launchd plist 的 `EnvironmentVariables` 注入 `DYLD_INSERT_LIBRARIES`，把动态库加载到 SpringBoard 等平台进程。
- 使用 MobileSubstrate/Substitute/ElleKit 等 hook 框架，把 tweak 动态库加载到目标进程；rootful 的配置通常在 `/Library/MobileSubstrate/DynamicLibraries`，rootless 则在 `/var/jb/Library/MobileSubstrate/DynamicLibraries`。
- 使用 `frida-server`、调试器或重签名应用，在用户态直接附加目标进程。

这些手段的共同前提是已经取得 root 或内核能力。仅仅安装一个企业证书应用，无法向 SpringBoard 注入动态库；仅仅有一个后台任务标识符，也无法让代码在重启后自动运行。持久化的门槛，始终是代码签名与 launchd 的注册权限。

### 4.4 典型的持久化组合

在越狱设备上，攻击者常见的组合是“LaunchDaemon + 注入 + 看门狗”：守护进程以 root 运行，负责在条件满足时拉起主植入体；主植入体注入 SpringBoard 或某个系统守护进程，获得图形界面与网络能力；另一个轻量看门狗通过 `KeepAlive` 或 `StartInterval` 监控主进程，发现退出后重新拉起。为了降低可见性，守护进程可能使用与系统服务相似的 Label、放在看似合法的路径下，并限制日志输出。

这套组合的弱点同样明显：所有组件都依赖越狱环境，设备重启后需要重新越狱才能恢复；plist、动态库、包管理器数据库与异常进程都会留下痕迹；一旦用户升级系统或恢复固件，持久化立即失效。对高级攻击链而言，越狱持久化适合长周期、低噪声的定向场景，但不适合需要“一次感染、永久控制”的大规模行动。

## 五、持久化技术谱系

### 5.1 用户态持久化

用户态是成本最低、可见性最高的层级。常见载体包括应用容器中的文件、Keychain 条目、App Group 共享容器、配置描述文件、Web Clip、快捷指令自动化与企业证书应用。它们的存活周期各不相同：应用容器随卸载删除，Keychain 条目在卸载后可能仍然存在（受条目属性与系统版本影响），App Group 容器在最后一个应用卸载后通常被清理，配置描述文件需要用户或 MDM 安装，且删除通常需要密码。

配置描述文件是一条被低估的持久化路径。攻击者可以诱导用户安装一个包含 VPN、代理、Wi-Fi 或 Web Clip 的描述文件，从而长期改变设备的网络行为；在受监督设备上，MDM 可以静默安装描述文件并强制合规，这既是企业的管理能力，也是攻击者觊觎的入口。描述文件本身不能执行任意代码，但它可以持久地改变信任配置与流量路径。

### 5.2 系统用户态持久化

系统用户态持久化依赖 root 或内核能力，典型载体是 LaunchDaemons/LaunchAgents、注入的系统进程、替换的系统二进制与修改的信任缓存。它的存活周期通常到下次重启或系统更新为止；在越狱设备上，可以通过引导脚本在每次启动时重新建立。检测这类持久化的关键，是比对 launchd 的服务清单、进程的签名与 entitlements、动态库加载列表，以及系统卷的完整性。

### 5.3 内核态与固件级持久化

iOS 不支持第三方内核扩展（kext），内核态的“持久化”通常表现为运行时的补丁与 hook：攻击者利用内核漏洞获得读写能力，修改内核数据结构、挂钩系统调用、绕过代码签名或隐藏进程。这些修改存在于内存中，重启即失效；要跨重启保留，必须在引导链的某个环节重新应用补丁。

固件级持久化则更深。BootROM 缺陷（例如公开研究中的 checkm8，影响 A11 及更早设备）无法通过软件更新修复，攻击者可以借此在每次启动时绕过安全启动并重新植入。iBoot、SEP 固件与基带固件的植入在理论上可行，但公开民用案例极少，技术门槛与风险都极高。就 Coruna/DarkSword 而言，公开资料没有披露其具备固件级持久化能力，本文不作推断。

| 层级 | 典型载体 | 所需权限 | 重启后存活 | 主要检测点 |
| --- | --- | --- | --- | --- |
| 应用/用户态 | 容器文件、Keychain、App Group、描述文件 | 应用沙箱或用户交互 | 部分（Keychain、描述文件） | 文件完整性、配置描述文件、钥匙串条目 |
| 系统用户态 | LaunchDaemon、LaunchAgent、注入的系统进程 | root / 越狱 | 越狱环境下可恢复，否则否 | launchd 清单、进程签名、动态库 |
| 内核态 | 内核补丁、hook、隐藏进程 | 内核读写 | 否（需重新应用） | 内核完整性、panic 日志、异常系统调用 |
| 引导链/固件 | BootROM、iBoot、SEP、基带 | 硬件级缺陷或内部能力 | 是 | 安全启动度量、DFU 恢复、硬件审计 |

这张表说明了一个常被忽略的事实：持久化的“强度”与“可见性”通常成正比。固件级植入最难清除，但也最难实施；应用级持久化最容易实施，但也最容易随卸载、恢复或系统更新消失。攻击者需要在这两者之间做工程权衡，防御者则应针对不同层级设计不同的检测与响应策略。

### 5.4 生存周期与检测成本

从生存周期看，Web 会话最短，应用容器次之，系统守护进程更长，内核补丁到重启为止，固件植入可能跨越系统重装。从检测成本看，顺序正好相反：Web 会话几乎不留痕迹，应用容器需要文件系统取证，守护进程需要比对 launchd 与签名，内核与固件则需要专业工具与硬件知识。企业安全团队应把有限的检测资源投入到“最可能被使用、且最可能留下痕迹”的层级，而不是追求对固件级威胁的全面覆盖。

### 5.5 无文件驻留与重新感染

“无文件”（fileless）并不神秘，它指的是攻击逻辑主要存在于内存、脚本解释器或合法进程的地址空间中，磁盘上只留下少量配置或加密数据。iOS 上的无文件形态通常包括：WebContent 中的 JavaScript、注入到系统进程的动态库、通过 URL Scheme 与 `NSUserActivity` 传递的参数，以及存放在应用容器中的加密载荷。它们的共同弱点是重启即失效，因此必须与重新感染机制配合。

重新感染是未越狱设备上最现实的“持久化”。攻击者可以控制一个长期存在的 Web 入口（水坑站点、被入侵的论坛、恶意广告），在用户每次访问时重新投递漏洞链；也可以通过短信、邮件、即时通讯发送恶意链接，把“用户点击”当作新的入口。对攻击者而言，这种方式的成本低于维持一个系统级植入；对防御者而言，这意味着单次取证可能看不到完整的攻击链，必须结合网络日志与多次事件的时间线。

常见的无文件载体包括：

- 内存马：只存在于进程地址空间，进程退出即消失，但可以在同一会话内反复执行。
- 脚本驻留：依赖页面、WebView 或 JavaScript 运行时，受标签页生命周期与节流策略限制。
- 合法进程寄生：注入 SpringBoard、sharingd、nsurlsessiond 等长生命周期进程，避免创建新进程。
- 配置残留：描述文件、Web Clip、Keychain 条目在卸载后仍可能存在，为下一次感染提供落脚点。

无文件驻留的检测重点不是文件哈希，而是行为：WebContent 进程的异常内存操作、非预期的动态库加载、应用进程中出现的陌生线程、以及脚本解释器与网络栈的异常组合。企业应把浏览器与 WebView 的版本管理、链接过滤与出口流量分析放在同等重要的位置。

## 六、Coruna/DarkSword 驻留与保活分析

### 6.1 Coruna 分阶段载荷的驻留需求

按任务背景与公开分析中的通行描述，Coruna 以 WebKit 远程入口加分阶段载荷为特征。分阶段载荷的工程优势是：第一阶段只需足够小、足够稳定，后续模块可以按需投递；缺点是每一阶段都需要解决“如何在不被杀死的前提下继续执行”。在未越狱设备上，这通常意味着：

- 把后续阶段驻留在 WebContent 或应用进程的内存中，依赖页面存活或应用再次启动。
- 通过沙箱逃逸进入更具权限的进程，利用系统进程的长期运行特性维持存在。
- 借助配置描述文件、MDM 或用户安装的应用获得跨重启的落脚点（需要用户交互）。
- 在取得内核能力后，通过 hook 或补丁隐藏进程与文件，但重启后仍需重新感染。

公开资料未披露 Coruna 的具体持久化实现，以上仅为基于 iOS 约束的推断。可以确定的是，任何不依赖越狱的持久化都必须跨过代码签名与 launchd 注册这两道门槛，否则只能停留在“重新感染”或“进程内驻留”的层面。

### 6.2 DarkSword 纯 JavaScript 的“无驻留”悖论

DarkSword 以纯 JavaScript 协同多个漏洞、较少依赖传统 Native Payload 为特征。纯脚本形态的优势是落地少、变形快、易于投递；劣势是执行环境受限，通常停留在 WebContent 沙箱内。WebContent 进程会被系统回收，标签页会被挂起，JavaScript 定时器会被节流，因此它很难实现传统意义上的系统级驻留。

由此可以推断，DarkSword 的“驻留”更可能是会话内潜伏与重新投递：在页面存活期间完成侦察、权限推进与数据回传；页面关闭或被回收后，依靠再次诱导访问、恶意广告、消息链接或水坑页面重新感染。它的持久性不来自设备上的某个文件，而来自攻击者对用户访问路径的控制。这也意味着，针对这类形态的检测重点应放在 WebContent 的异常行为、网络回连与页面生命周期，而不是寻找一个不存在的守护进程。

### 6.3 可能的保活组合（推断）

如果把两种形态放在同一张能力图上，可以推测出几种保活组合，但均需标注为推断：

- 纯会话型：仅存在于 WebContent 或应用进程内存，关闭即消失，依靠重新投递恢复。
- 应用内驻留型：通过注入或重打包进入某个已安装应用，借助该应用的后台模式（音频、定位、蓝牙、后台刷新）延长生命周期。
- 系统进程注入型：在取得沙箱逃逸与 root 后，注入 SpringBoard、sharingd、nsurlsessiond 等长期运行的进程，避免自己创建新进程。
- 守护进程型：仅在越狱设备上可行，通过 LaunchDaemon 与 KeepAlive 实现开机自启与崩溃重启。
- 配置持久化型：通过描述文件、MDM、Web Clip 或企业证书应用获得跨重启的落脚点，通常需要用户或组织管理员配合。

这些组合的共同点是：越靠近系统底层，越需要更高的漏洞能力与更复杂的工程；越靠近用户态，越依赖用户行为与重新感染。Coruna 与 DarkSword 的具体选择，公开资料未披露，本文不做归因。

### 6.4 公开资料未披露的部分

截至本文写作时，Coruna 与 DarkSword 的完整工具链、持久化组件、命令与控制协议、以及是否使用特定内核或固件缺陷，均缺乏公开细节。本文不推测其使用某个具体 LaunchDaemon 路径、某个特定描述文件标识符或某个未公开的 iOS 漏洞，也不给出未经证实的 CVE 编号。可讨论的是能力类别与防御原则：远程入口、沙箱推进、进程注入、凭证收集、保活外传，这些环节的检测与加固并不依赖于精确归因。

## 七、检测（崩溃日志、launchd、电量与网络异常）

### 7.1 崩溃日志、panic 与 sysdiagnose

iOS 的崩溃日志是低成本、高价值的取证来源。设备上可在“设置 > 隐私与安全性 > 分析与改进 > 分析数据”中查看，文件通常位于 `/var/mobile/Library/Logs/CrashReporter/`（路径随版本略有差异），包括应用崩溃、 jetsam 内存终止与 `panic-full` 一类的内核日志。异常的模式包括：同一进程反复崩溃、崩溃线程停留在可疑的动态库、崩溃地址落在非预期的镜像、以及大量来自被注入进程的异常退出。

`sysdiagnose` 是更完整的诊断包，包含系统日志、进程列表、launchd 状态、电源与网络诊断、以及部分崩溃日志。企业取证时应先保留 sysdiagnose，再进行恢复或重装；对疑似内核级威胁，panic 日志与启动链度量往往比应用日志更有价值。

### 7.2 launchd 与进程清单

在越狱设备或取得 root 的诊断环境中，可以直接检查 launchd 的服务清单：

```text
launchctl print system
launchctl print system/com.example.agent
launchctl list
ps -A -o pid,ppid,user,comm
```

关注点包括：非 Apple 的 Label、位于 `/Library/LaunchDaemons` 或 `/var/jb/Library/LaunchDaemons` 的 plist、`RunAtLoad` 与 `KeepAlive` 同时为真的服务、指向 `/tmp`、`/var/tmp` 或用户可写目录的 `ProgramArguments`、以及以 root 运行但没有签名的二进制。`launchctl print` 还会显示服务的状态、最近退出码与 PID，有助于识别崩溃循环。

在未越狱设备上，普通应用无法读取这些信息；企业应通过 MDM、sysdiagnose 与受控的取证工具获取，而不是依赖应用内的“越狱检测”接口。

### 7.3 电量、网络与唤醒异常

后台滥用的共同副作用是电量与网络异常。可观测信号包括：某应用的后台活动时间显著高于同类应用、夜间持续唤醒、蜂窝流量在锁屏后仍然增长、设备发热、以及电池用量页面出现与用户认知不符的后台记录。企业侧可以结合 MDM 的合规数据、DNS 日志与出口流量分析，识别周期性回连、短连接心跳、以及指向新注册域名的 TLS 会话。

网络层不应只依赖域名黑名单。高级攻击链会使用云存储、CDN、合法服务作为中继；更有意义的信号是“行为”：固定的信标间隔、非工作时间的批量上传、与用户地理位置不符的连接、以及应用在后台却产生持续流量。

对 APNs 流量的分析也有价值：静默推送与 MDM 推送都经由 Apple 的推送基础设施，企业通常无法解密内容，但可以观察推送后的唤醒频率、连接目标与数据量变化。若某设备在锁屏后规律性地出现“短唤醒—加密连接—小流量上传”的循环，应结合应用清单与 MDM 配置排查，而不是仅凭单次告警定性。

### 7.4 企业侧检测与响应

企业应把移动端威胁狩猎纳入现有流程：定期审查 MDM 设备清单与描述文件、比对异常应用与证书、监控高风险管理岗位的设备姿态、对越狱特征与调试状态告警、保留 sysdiagnose 与网络日志、建立“疑似失陷”的处置剧本。处置顺序应是：隔离网络、保留证据、撤销会话与令牌、轮换凭证、检查 MDM 与描述文件、必要时擦除并重装最新系统。不要在没有取证的情况下直接重启或恢复，以免丢失内存与运行时证据。

## 八、加固建议

### 8.1 应用侧

- 只声明真正需要的后台模式。每增加一个 `UIBackgroundModes` 条目，都会扩大攻击面与审核风险；音频、定位、蓝牙尤其需要业务合理性。
- 使用 BackgroundTasks 时，正确实现 `expirationHandler` 与 `setTaskCompleted`，避免长任务与忙等；不要用后台刷新承载关键同步。
- 不要用静音音频、空转定位或伪造蓝牙事件保活。这些做法既违反审核规则，也容易被电量与音频会话监控识别。
- 对后台 URLSession 的恢复事件做完整性与来源校验，限制后台传输的大小与目标域名。
- 对推送负载做最小化处理，不把敏感数据放在通知内容中；对静默推送触发的拉取做签名校验与重放防护。
- 把长期令牌放入受 Keychain ACL 保护的条目，缩短会话有效期，服务端支持撤销与设备解绑。

### 8.2 系统与设备侧

- 保持系统更新，及时应用快速安全响应（Rapid Security Response）；高风险管理岗位启用 Lockdown Mode。
- 启用“失窃设备保护”（iOS 17.3 起），减少密码回退与物理控制带来的风险；开启 USB 配件限制，降低物理取证攻击面。
- 不要安装来源不明的描述文件、企业证书应用或 Web Clip；定期在“设置 > 通用 > VPN 与设备管理”中审查并删除不再需要的配置。
- 越狱设备不应接入企业邮箱、即时通讯与云盘；如必须使用，应隔离到独立设备与独立账号。
- 对设备进行加密备份，但不要把高价值令牌与生物识别保护的数据纳入明文备份；启用高级数据保护时需评估恢复流程。

### 8.3 企业侧

- 用 MDM 强制最低系统版本、锁屏密码、设备加密与合规基线；对受监督设备限制描述文件安装与配对。
- 建立应用白名单与证书固定策略，监控异常企业证书应用与非 App Store 分发渠道。
- 对高风险管理岗位部署独立的威胁检测与取证能力，定期检查 launchd 异常、进程签名与网络回连。
- 把“设备失陷”纳入身份安全预案：会话撤销、令牌轮换、条件访问、以及针对异常登录的强制重新认证。
- 对 Coruna/DarkSword 一类威胁，优先防御远程入口与凭证窃取，而不是追逐尚未公开的持久化细节；更新、最小权限、网络分段与快速响应，仍然是最有效的组合。

## 九、结语

iOS 的后台执行模型把“常驻”变成了一种需要系统批准的特权，第三方应用只能在有限的窗口内工作。越狱打破了这层限制，但也把设备带入了另一个可见性更高的世界：LaunchDaemons、注入的动态库、异常的进程与 plist，都会成为取证与检测的锚点。Coruna 与 DarkSword 的差异，本质上也是工程权衡的差异：分阶段载荷需要解决驻留与权限推进，纯 JavaScript 形态则更依赖会话与重新投递。

对防御者而言，重要的不是记住某个守护进程路径或某个 API，而是理解这套系统的权力结构：谁能注册服务，谁能签名代码，谁能决定进程何时运行。把应用的后台需求压到最小，把设备的配置与进程纳入持续监控，把身份与会话设计成可撤销、可绑定、可验证的形态，才能在这条从 BackgroundTasks 到 launchd 的链条上，守住真正关键的边界。
