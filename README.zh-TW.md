# Claude Skill Antivirus

[![npm version](https://img.shields.io/npm/v/claude-skill-antivirus.svg)](https://www.npmjs.com/package/claude-skill-antivirus)
[![CI](https://github.com/claude-world/claude-skill-antivirus/actions/workflows/ci.yml/badge.svg)](https://github.com/claude-world/claude-skill-antivirus/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/node-%3E%3D22.0.0-brightgreen.svg)](https://nodejs.org/)
[![Claude Code](https://img.shields.io/badge/Claude_Code-Opus_5.5-blueviolet.svg)](https://docs.anthropic.com/en/docs/claude-code)

一個安全的 Claude Skills 安裝器，內建完整的惡意行為偵測引擎。

**Skills Installer + Antivirus for Claude**

支援 Claude Code Opus 5.5、Sonnet 5.5、Haiku 5.5、Fable 5.1 模型。本工具會掃描整個 skill 目錄（不只 SKILL.md）。

[English](./README.md) | [SkillsMP 掃描報告](./SCAN-REPORT.md)

## SkillsMP 平台掃描結果

我們掃描了 SkillsMP 上所有 **71,577 個 skills**：

| 風險等級 | 數量 | 百分比 |
|----------|------|--------|
| 嚴重 | 91 | 0.13% |
| 高 | 626 | 0.87% |
| 中 | 1,310 | 1.83% |
| 安全 | **69,505** | **97.11%** |

**約 3% 的 skills 可能存在潛在風險。** 詳見[完整報告](./SCAN-REPORT.md)。

> **覆蓋範圍說明**：此平台掃描（v2.0.0，2026 年 1 月）使用 SkillsMP API，而該 API 只提供每個 skill 的 `SKILL.md`，因此這裡的「安全」僅代表 manifest 中沒有發現；腳本並未被分析（見 [#33](https://github.com/claude-world/claude-skill-antivirus/issues/33)）。若要取得完整結果，請掃描 skill 的目錄或儲存庫。

> **注意**：部分發現可能是誤判（例如：合法的 1Password/Bitwarden 整合工具）。建議對標記的 skills 進行人工審查。

## 功能特色

- **🛡️ 十大掃描引擎**: 全方位偵測惡意 Skills（掃描整個目錄，不只 SKILL.md）
- **⚠️ 風險評估**: 將發現分類為 Critical、High、Medium、Low、Info
- **📊 視覺化報告**: 彩色安全報告與分數
- **🚫 自動阻擋**: 預設阻擋 CRITICAL 風險的 Skills
- **🌐 支援多來源**: SkillsMP、GitHub、本機檔案
- **🌍 多語言支援**: 英文和繁體中文

## 安裝

```bash
npm install -g claude-skill-antivirus
```

或不安裝、直接以 npx 執行：

```bash
npx claude-skill-antivirus <skill-source>
npx claude-skill-antivirus ./path/to/skill --scan-only
```

## 使用方式

### 安裝 Skill（含安全掃描）

```bash
# 安裝到專案層級 (./.claude/skills/) - 預設
skill-install ./path/to/skill
skill-install https://github.com/user/skill-repo

# 安裝到使用者層級 (~/.claude/skills/)
skill-install ./path/to/skill --global
skill-install @skillsmp/example-skill -g
```

**安裝路徑：**
- 專案層級（預設）：`./.claude/skills/`
- 使用者層級（`--global`）：`~/.claude/skills/`

### 僅掃描（不安裝）

```bash
skill-install ./path/to/skill --scan-only
```

### 變更語言

```bash
# 英文（預設）
skill-install ./path/to/skill --lang en

# 繁體中文
skill-install ./path/to/skill --lang zh-TW
```

### 指令名稱

全域安裝後會提供三個可互換的安裝器指令，上面的範例使用任何一個都可以：

```bash
claude-skill-antivirus ./path/to/skill --scan-only
skill-install ./path/to/skill --scan-only
claude-skill-av ./path/to/skill --scan-only
```

`skill-batch-scan` 則是下一節說明的批量掃描工具。

### 批量掃描所有 SkillsMP 技能

```bash
# 掃描 SkillsMP 上的所有技能（需要 API 金鑰）
skill-batch-scan --api-key <your-api-key>

# 使用選項掃描
skill-batch-scan --api-key <key> --max-pages 10 --verbose
skill-batch-scan --api-key <key> --output ./my-reports --lang zh-TW
```

選項：
- `-k, --api-key <key>` - SkillsMP API 金鑰（必填）
- `-l, --limit <number>` - 每頁技能數（預設：100）
- `-p, --max-pages <number>` - 最大掃描頁數（預設：全部）
- `-o, --output <dir>` - 報告輸出目錄（預設：./scan-reports）
- `-v, --verbose` - 顯示詳細輸出
- `--lang <lang>` - 語言（en, zh-TW）

## 掃描引擎

### 1. 危險指令偵測 (DangerousCommandScanner)

偵測可能造成系統損害的指令：

| 風險等級 | 偵測項目 |
|----------|----------|
| Critical | `rm -rf /`、`curl \| bash`、fork bomb |
| High | 讀取 `/etc/shadow`、reverse shell、憑證竊取 |
| Medium | `rm -rf`、權限變更、服務控制 |
| Low | `sudo`、全域安裝 |

### 2. 權限範圍檢查 (PermissionScanner)

分析 `allowed-tools` 宣告：

- **Critical**: `Bash(*)` - 無限制 shell 存取
- **High**: `Write`、`WebFetch`、廣泛的 bash 權限
- **Medium**: `Read`、`Glob`、`Grep`、版本控制工具
- **危險組合偵測**: 例如 `Read + WebFetch` = 資料外洩風險

### 3. 外部連線分析 (ExternalConnectionScanner)

識別可疑的網路活動：

- IP 直連 URL
- Webhook/資料擷取服務
- 可疑 TLD (.tk、.ml 等)
- Discord/Telegram webhook
- URL 縮短服務

### 4. 模式匹配 (PatternScanner)

偵測：

- Prompt injection 攻擊
- 硬編碼的憑證/API 金鑰
- 混淆程式碼 (base64、hex 編碼)
- 社交工程語言

### 5. 資料外洩偵測 (DataExfiltrationScanner)

**專門偵測讀取本機資料並傳送到外部的惡意行為**：

| 類別 | 偵測項目 |
|------|----------|
| 資料收集 | 讀取 `.ssh`、`.aws`、`.env`、瀏覽器密碼、密碼管理器 |
| 資料外洩 | `curl -d`、`nc` 傳送、DNS tunneling、郵件外洩 |
| 組合攻擊 | `cat \| base64 \| curl`、`tar \| nc`、`find -exec curl` |
| 環境變數竊取 | `env \| curl`、`printenv` 外洩 |
| 系統偵察 | `whoami`、`hostname`、網路設定外洩 |
| 持久化機制 | 修改 `.bashrc`、cron 定時外洩 |

### 6. MCP Server 安全檢查 (MCPSecurityScanner)

**偵測 MCP Server 設定中的安全風險**：

| 類別 | 偵測項目 |
|------|----------|
| 不受信任來源 | 非官方 MCP server、從 URL 直接執行 |
| 危險權限 | Filesystem 無限制存取、Shell 執行、資料庫存取 |
| 敏感設定 | 環境變數含憑證、設定檔暴露 |
| 危險組合 | Filesystem + Fetch、Shell + 網路 |

### 7. SSRF/雲端攻擊偵測 (SSRFScanner)

**偵測 Server-Side Request Forgery 和雲端攻擊**：

| 類別 | 偵測項目 |
|------|----------|
| 雲端 Metadata | AWS/GCP/Azure 169.254.169.254、IAM 憑證竊取 |
| 內部網路 | 10.x.x.x、192.168.x.x、172.16-31.x.x 探測 |
| SSRF 繞過 | Hex IP、URL 編碼、file://、gopher:// |
| Kubernetes | API 存取、secrets 竊取、serviceaccount |
| Docker | docker.sock 存取、特權容器、容器逃逸 |

### 8. 依賴安全檢查 (DependencyScanner)

**偵測惡意或有漏洞的依賴套件**：

| 類別 | 偵測項目 |
|------|----------|
| 已知惡意套件 | event-stream、ua-parser-js、colors、faker |
| Typosquatting | crossenv、lodash-、mongose、reqeusts |
| 可疑安裝 | 從 URL 安裝、不安全 registry、HTTP index |
| postinstall 風險 | install 腳本含 curl、wget、eval |

### 9. Sub-agent 攻擊偵測 (SubAgentScanner)

**偵測 Task 工具和 Sub-agent 的濫用**：

| 類別 | 偵測項目 |
|------|----------|
| 權限升級 | Task 派生 Bash agent、要求所有權限 |
| Prompt Injection | Sub-agent prompt 含惡意指令 |
| Agent 鏈攻擊 | 嵌套 Task 呼叫、遞迴 agent |
| DoS 攻擊 | 迴圈呼叫 Task、無限遞迴 |
| 資料竊取 | Read + WebFetch 組合、存取敏感資料 |

### 10. 檔案工件偵測 (FileArtifactScanner)

**標記無法以文字審查、常被用來藏匿 payload 的非文字工件**：

| 類別 | 偵測項目 |
|------|----------|
| 編譯 / 原生檔 | `.pyc`、`.pyo`、`.so`、`.node`、`.dll`、`.dylib`、`.exe`、`.wasm`、`.class` |
| 壓縮檔 | skill 內夾帶的 `.zip`、`.tar`、`.gz`、`.7z`、`.jar`、`.whl` |
| 二進位內容 | 以內容判定的非文字檔，只掃描其可讀字串 |
| 覆蓋率異常 | 非預期目錄、未跟隨的 symlink、被截斷的檔案、掃描上限 |

## 輸出範例

### 安全的 Skill

```
🔧 Claude Skill Installer v2.2.1

📦 已載入 Skill: example-safe-skill

🔍 開始安全掃描...

===========================================
          安全掃描報告
===========================================
風險等級: ✅ 安全

📊 發現摘要:
  🟢 嚴重: 0
  🟢 高:   0
  🟢 中:   0
  🟢 低:   0
  ℹ️  資訊: 2

✅ 建議: 可以安全安裝
```

### 偵測到惡意 Skill

```
🔧 Claude Skill Installer v2.2.1

📦 已載入 Skill: suspicious-skill

🔍 開始安全掃描...

===========================================
          安全掃描報告
===========================================
風險等級: ☠️ 嚴重

📊 發現摘要:
  🔴 嚴重: 5
  🟠 高:   3
  🟡 中:   2
  🟢 低:   1
  ℹ️  資訊: 4

🔴 嚴重發現:
  • [資料收集] 讀取敏感憑證檔案
    嘗試讀取環境變數、私鑰或憑證檔案
  • [資料外洩] curl 傳送指令輸出
    使用 curl 將指令執行結果傳送到外部伺服器
  ...

❌ 建議: 請勿安裝 - 包含嚴重安全風險
```

## 風險等級

| 等級 | 分數影響 | 動作 |
|------|----------|------|
| CRITICAL | -30/項 | 阻止安裝 |
| HIGH | -20/項 | 需明確確認 |
| MEDIUM | -10/項 | 顯示警告 |
| LOW | -5/項 | 詳細模式顯示 |
| INFO | 0 | 總是顯示 |

## API

您也可以程式化使用掃描器：

```javascript
import { SecurityScanner, loadSkill } from 'claude-skill-antivirus';

const scanner = new SecurityScanner();
const skill = await loadSkill('./path/to/skill');
const findings = await scanner.scan(skill);

console.log(findings);
// {
//   critical: [...],
//   high: [...],
//   medium: [...],
//   low: [...],
//   info: [...]
// }
```

## 專案結構

```
claude-skill-antivirus/
├── src/
│   ├── index.js                   # CLI 入口
│   ├── i18n/                      # 國際化
│   │   ├── index.js
│   │   ├── en.js                  # 英文翻譯
│   │   └── zh-TW.js               # 繁體中文翻譯
│   ├── lib.js                     # 程式化 API 入口（無 CLI 副作用）
│   ├── version.js                 # 版本號的唯一來源
│   ├── scanner/
│   │   ├── index.js               # 主掃描器（整合 10 個引擎）
│   │   ├── dangerous-commands.js  # 危險指令偵測
│   │   ├── permissions.js         # 權限檢查
│   │   ├── external-connections.js # 外部連線分析
│   │   ├── patterns.js            # 模式匹配
│   │   ├── data-exfiltration.js   # 資料外洩偵測
│   │   ├── mcp-security.js        # MCP Server 安全檢查
│   │   ├── ssrf-scanner.js        # SSRF/雲端攻擊偵測
│   │   ├── dependency-scanner.js  # 依賴安全檢查
│   │   ├── subagent-scanner.js    # Sub-agent 攻擊偵測
│   │   └── file-artifacts.js      # 編譯／二進位／壓縮工件偵測
│   └── utils/
│       ├── downloader.js          # Skill 載入器（走訪整個目錄）
│       └── installer.js           # Skill 安裝器
├── examples/
│   ├── safe-skill/                # 安全範例
│   ├── malicious-skill/           # 惡意範例（測試所有引擎）
│   └── hidden-code-skill/         # 藏碼範例（payload 在 SKILL.md 之外，#33）
├── test/
│   ├── scan.test.js               # 迴歸測試（node --test）
│   └── bin.test.js                # 確認每個 bin 可解析並會被打包
├── package.json
└── README.md
```

## 更新紀錄

### v2.2.1 (2026-10-21)
- **修復文件中的 `npx claude-skill-antivirus` 指令**：先前因為沒有與套件同名的 bin，執行時會出現「could not determine executable to run」。現在 `claude-skill-antivirus` 與 `skill-install`、`claude-skill-av` 並列為 bin 別名，並新增測試確認每個宣告的 bin 都能解析、執行 `--version`，且確實打包進 tarball。
- `--help` 現在會顯示你實際輸入的指令名稱，而非一律印出 `skill-install`。
- npm 發布改用[信任發布](https://docs.npmjs.com/trusted-publishers)（OIDC），發布帶有 provenance 簽章，CI 中不再存放長期有效的 npm token。

### v2.2.0 (2026-10-21)
- **安全修復（[#33](https://github.com/claude-world/claude-skill-antivirus/issues/33)）**：掃描器現在會走訪**整個 skill 目錄**，而非只讀取 `SKILL.md`，因此藏在 `scripts/`、巢狀資料夾或 `__pycache__/*.pyc` 的程式碼不再能騙過掃描而得到 SAFE 100/100。由 [@nedlir](https://github.com/nedlir) 回報；目錄走訪基礎由 [@Yahhi](https://github.com/Yahhi) 貢獻（[#34](https://github.com/claude-world/claude-skill-antivirus/pull/34)）。
- 新增**檔案工件偵測**引擎（第 10 個），以檔頭魔數標記編譯／二進位／壓縮檔；PEP 552 未檢查雜湊的 `.pyc` 列為 CRITICAL；被略過的目錄、未跟隨的 symlink、截斷的檔案與掃描上限都會列為發現。
- GitHub 儲存庫、`tree/` 與 `blob/.../SKILL.md` 網址會透過 GitHub API 走訪整個 skill；`.zip` 輸入新增 zip-slip、加密／過大項目偵測與大小上限。
- 安裝器強化：拒絕 zip-slip 路徑與未完整掃描的 skill，並逐位元組寫入二進位檔。
- 修復各引擎的 ReDoS（特製的超長行可能使掃描器卡住），以及 SKILL.md 含 `| name |` 表格時的當機。
- 因應掃描實際程式碼調整比對精準度。附帶腳本的 skill 會比 2.1.x 顯示更多發現，請逐一檢視。
- 確認相容 Claude Code Opus 5.5、Sonnet 5.5、Haiku 5.5、Fable 5.1。
- Node.js >= 22；升級相依套件（commander 15、inquirer 14、chalk 6、ora 9、yaml 2.9、adm-zip 0.6），並以內建 `fetch` 取代 `node-fetch`。

### v2.1.0 (2026-03-13)
- 確認相容 Claude Code Opus 4.6
- 更新文件與中繼資料

### v2.0.1
- 權限掃描器分離能力警告與實際威脅
- 修復 `allowed-tools` 的陣列格式處理

### v2.0.0
- 新增 4 個掃描引擎：MCP 安全、SSRF、依賴、Sub-agent 偵測（共 9 個引擎）
- 新增多語言支援（英文 + 繁體中文）
- 新增 SkillsMP 批次掃描功能
- 掃描 SkillsMP 上所有 71,577 個技能

### v1.0.0
- 首次發布，包含 5 個核心掃描引擎
- CLI 安裝器，含互動式提示

## 相關專案

- [cf-browser](https://github.com/claude-world/cf-browser) - 開源 Cloudflare 瀏覽器渲染代理，提供 9 個 MCP 工具給 Claude Code 使用
- [claude-world.com](https://claude-world.com) - Claude Code 進階使用社群

## 貢獻

歡迎貢獻！請隨時提交 issues 和 pull requests。

### 新增偵測模式

每個掃描器都是模組化的。要新增模式：

1. 在 `src/scanner/` 找到適當的掃描器
2. 將您的模式新增到相關陣列
3. 包含：`pattern`、`risk`、`title`、`description`

## License

MIT

## 作者

Lucas Wang <support@claude-world.com>

## 連結

- [GitHub Repository](https://github.com/claude-world/claude-skill-antivirus)
- [npm 套件](https://www.npmjs.com/package/claude-skill-antivirus)
- [回報問題](https://github.com/claude-world/claude-skill-antivirus/issues)
