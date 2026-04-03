/**
 * Traditional Chinese language messages for Claude Skill Antivirus
 */
export const zhTW = {
  // CLI messages
  cli: {
    title: 'Claude Skill 安裝器 v2.1.3',
    fetching: '正在獲取 skill 內容...',
    skillLoaded: 'Skill 載入完成: {name}',
    startingScan: '開始安全掃描...',
    scanComplete: '掃描完成（--scan-only 模式）',
    installBlocked: '因 CRITICAL 安全風險，安裝已被阻止。',
    useAllowHighRisk: '使用 --allow-high-risk 覆蓋（不建議）',
    confirmInstall: 'Skill 風險等級為 {riskLevel}。是否繼續安裝？',
    installCancelled: '使用者取消安裝。',
    installing: '正在安裝 skill...',
    installedTo: 'Skill 已安裝至: {path}',
    installComplete: '安裝完成！',
    error: '錯誤',
  },

  // Report headers
  report: {
    title: '安全掃描報告',
    riskLevel: '風險等級:',
    score: '分數:',
    findingsSummary: '發現摘要:',
    critical: '嚴重:',
    high: '高:',
    medium: '中:',
    low: '低:',
    info: '資訊:',
    criticalIssues: '嚴重問題:',
    highIssues: '高風險問題:',
    mediumIssues: '中等問題:',
    lowIssues: '低風險問題:',
    infoItems: '資訊:',
    location: '位置',
  },

  // Risk level names
  riskLevels: {
    CRITICAL: '嚴重',
    HIGH: '高風險',
    MEDIUM: '中風險',
    LOW: '低風險',
    SAFE: '安全',
  },

  // Recommendations
  recommendations: {
    critical: '請勿安裝 - 此 skill 包含嚴重的安全風險，可能損害您的系統。',
    high: '不建議安裝 - 請仔細審查所有高風險發現後再繼續。',
    medium: '謹慎進行 - 偵測到一些潛在風險模式。',
    low: '一般安全 - 偵測到輕微問題，使用前請審查。',
    safe: '可安全安裝 - 未偵測到顯著的安全問題。',
  },

  // Scanner categories
  categories: {
    dataCollection: '資料收集',
    dataExfiltration: '資料外洩',
    combinedAttack: '組合攻擊',
    envTheft: '環境變數竊取',
    systemRecon: '系統偵察',
    persistence: '持久化機制',
    behaviorAnalysis: '行為分析',
    cloudMetadata: '雲端 Metadata',
    internalNetwork: '內部網路',
    internalService: '內部服務',
    ssrfBypass: 'SSRF 繞過',
    kubernetes: 'Kubernetes',
    docker: 'Docker',
    aws: 'AWS',
    privilegeEscalation: '權限升級',
    dangerousPrompt: '危險 Prompt',
    agentChain: 'Agent 鏈',
    dosAttack: 'DoS 攻擊',
    dataTheft: '資料竊取',
    background: '背景執行',
    untrustedType: '不受信任類型',
  },

  // DangerousCommandScanner
  dangerousCommands: {
    recursiveDeleteRoot: {
      title: '遞迴刪除根目錄/家目錄',
      description: '指令嘗試從根目錄或家目錄遞迴刪除檔案',
    },
    recursiveDeleteWildcard: {
      title: '使用萬用字元遞迴刪除',
      description: '指令使用萬用字元進行遞迴刪除 - 極度危險',
    },
    filesystemFormat: {
      title: '檔案系統格式化指令',
      description: '指令嘗試格式化檔案系統',
    },
    directDiskWrite: {
      title: '直接寫入磁碟',
      description: '指令直接寫入磁碟裝置',
    },
    forkBomb: {
      title: '偵測到 Fork bomb',
      description: '經典的 fork bomb 模式，可能導致系統崩潰',
    },
    diskRedirect: {
      title: '直接寫入磁碟',
      description: '將輸出直接重導向到磁碟裝置',
    },
    worldWritableRoot: {
      title: '根目錄設為全域可寫',
      description: '在根檔案系統設定危險的權限',
    },
    curlPipeShell: {
      title: '將 URL 直接導入 shell',
      description: '下載並執行遠端程式碼而不驗證',
    },
    wgetPipeShell: {
      title: '將下載內容導入 shell',
      description: '下載並執行遠端程式碼而不驗證',
    },
    evalSubstitution: {
      title: '使用命令替換的 eval',
      description: '可執行任意程式碼的危險模式',
    },
    readSensitiveFiles: {
      title: '讀取敏感系統檔案',
      description: '嘗試讀取密碼檔案或私鑰',
    },
    readCryptoKeys: {
      title: '讀取加密金鑰',
      description: '嘗試讀取私鑰或憑證',
    },
    envManipulation: {
      title: '環境變數操作',
      description: '設定或匯出敏感環境變數',
    },
    envExfiltration: {
      title: '環境變數外洩嘗試',
      description: '將環境變數導出可能洩漏機密',
    },
    netcatListener: {
      title: 'Netcat 監聽器/反向 shell',
      description: '設定網路監聽器，可能用於後門',
    },
    pythonSocket: {
      title: 'Python socket 單行程式',
      description: '內嵌 Python 網路程式碼 - 常用於反向 shell',
    },
    base64DecodeShell: {
      title: 'Base64 解碼到 shell',
      description: '混淆的命令執行',
    },
    sshSecurityBypass: {
      title: 'SSH 安全繞過',
      description: '停用 SSH 主機金鑰驗證',
    },
    certVerificationDisabled: {
      title: '憑證驗證已停用',
      description: '下載時不驗證 SSL 憑證',
    },
    passwordlessSudo: {
      title: '無密碼 sudo 設定',
      description: '嘗試設定無密碼 sudo 存取',
    },
    recursiveDelete: {
      title: '遞迴刪除指令',
      description: '使用 rm 的遞迴旗標 - 請仔細驗證目標',
    },
    permissionChange: {
      title: '權限修改',
      description: '變更檔案權限',
    },
    ownershipChange: {
      title: '所有權修改',
      description: '變更檔案所有權',
    },
    cronModification: {
      title: 'Cron 排程修改',
      description: '修改排程任務',
    },
    serviceControl: {
      title: '系統服務操作',
      description: '控制系統服務',
    },
    firewallConfig: {
      title: '防火牆設定',
      description: '修改防火牆規則',
    },
    forceKill: {
      title: '強制終止指令',
      description: '強制終止程序',
    },
    bulkKill: {
      title: '批量程序終止',
      description: '依名稱終止多個程序',
    },
    sudoUsage: {
      title: '使用 sudo',
      description: '指令需要提升權限',
    },
    globalNpmInstall: {
      title: '全域 npm 安裝',
      description: '全域安裝 npm 套件',
    },
    systemPipInstall: {
      title: '系統級 pip 安裝',
      description: '系統級安裝 Python 套件',
    },
    gitClone: {
      title: 'Git clone 操作',
      description: '複製遠端儲存庫',
    },
    hexEncoded: {
      title: '偵測到十六進位編碼內容',
      description: '內容包含可能隱藏惡意程式碼的十六進位字串',
    },
    base64EncodedCommands: {
      title: 'Base64 編碼的 shell 指令',
      description: '在 base64 編碼內容中發現隱藏的 shell 指令',
    },
    unicodeEscape: {
      title: '偵測到 Unicode 跳脫序列',
      description: '內容包含可能混淆程式碼的 unicode 跳脫',
    },
  },

  // PermissionScanner
  permissions: {
    noExplicitTools: {
      title: '無明確工具權限',
      description: 'Skill 未宣告 allowed-tools - 可能使用預設值',
    },
    criticalTool: {
      title: 'CRITICAL 風險工具',
      description: 'Shell 命令執行 - 可執行任何系統命令',
    },
    highTool: {
      title: 'HIGH 風險工具',
      description: '具有潛在危險能力的高風險工具',
    },
    mediumTool: {
      title: 'MEDIUM 風險工具',
      description: '具有顯著存取權限的中風險工具',
    },
    lowTool: {
      title: 'LOW 風險工具',
      description: '能力有限的低風險工具',
    },
    unrestrictedBash: {
      title: '無限制 Bash 存取',
      description: 'Skill 具有無限制的 shell 存取 - 可執行任何命令',
    },
    wildcardBash: {
      title: '萬用字元 Bash 權限',
      description: 'Bash 權限使用萬用字元 - 過於廣泛的存取',
    },
    wildcardPermission: {
      title: '工具權限中的萬用字元',
      description: '權限中的萬用字元可能授予超出必要的存取',
    },
    dangerousCombination: {
      title: '偵測到危險工具組合',
      description: '工具組合構成安全風險',
    },
    toolCount: {
      title: '已宣告工具權限',
      description: '允許的工具',
    },
    toolDescriptions: {
      Bash: 'Shell 命令執行 - 可執行任何系統命令',
      'Bash(*)': '無限制 shell 存取 - 最高風險',
      Write: '檔案寫入能力 - 可修改或建立任何檔案',
      Edit: '檔案編輯能力 - 可修改現有檔案',
      Read: '檔案讀取能力 - 可存取任何可讀檔案',
      Glob: '檔案探索 - 可尋找符合模式的檔案',
      Grep: '內容搜尋 - 可搜尋檔案內容',
      WebFetch: '外部 HTTP 請求 - 可存取網路資源',
      Task: 'Sub-agent 產生 - 可建立自主子程序',
      Delete: '檔案刪除 - 可移除檔案和目錄',
    },
  },

  // ExternalConnectionScanner
  externalConnections: {
    directIP: {
      title: '直接 IP 位址 URL',
      description: '直接指向 IP 位址的 URL 常用於繞過網域封鎖',
    },
    localhost: {
      title: 'Localhost URL 參考',
      description: 'localhost 參考可能表示除錯程式碼或本地服務利用',
    },
    loopback: {
      title: 'Loopback 位址 URL',
      description: '127.0.0.1 參考 - 與 localhost 類似的風險',
    },
    webhookSite: {
      title: 'Webhook 測試服務',
      description: 'Webhook.site URL 可能用於資料外洩',
    },
    requestCapture: {
      title: '請求擷取服務',
      description: '常用於擷取和外洩 HTTP 請求的服務',
    },
    tunnelService: {
      title: '隧道服務 URL',
      description: '隧道服務可能暴露內部資源或外洩資料',
    },
    pasteService: {
      title: '貼上服務 URL',
      description: '貼上服務可能用於託管惡意酬載',
    },
    discordWebhook: {
      title: 'Discord webhook',
      description: 'Discord webhook 可能用於資料外洩',
    },
    slackAPI: {
      title: 'Slack API 端點',
      description: 'Slack API 呼叫 - 驗證是否已授權',
    },
    telegramBot: {
      title: 'Telegram bot API',
      description: 'Telegram bot API 可能用於命令和控制',
    },
    urlShortener: {
      title: 'URL 縮短器',
      description: '縮短的 URL 隱藏實際目的地',
    },
    curlPostCommand: {
      title: 'Curl POST 帶命令輸出',
      description: '將命令輸出發送到外部伺服器',
    },
    curlPostVariable: {
      title: 'Curl 帶變數展開的資料',
      description: '將變數資料發送到外部伺服器',
    },
    wgetPost: {
      title: 'Wget POST 請求',
      description: '透過 wget POST 發送資料',
    },
    fetchPost: {
      title: 'JavaScript fetch POST',
      description: '透過 JavaScript fetch 發送資料',
    },
    xhrRequest: {
      title: 'XHR/ActiveX 請求',
      description: '舊版 HTTP 請求方法',
    },
    suspiciousTLD: {
      title: '可疑 TLD',
      description: 'URL 使用通常與惡意活動相關的 TLD',
    },
    unusualPort: {
      title: '不尋常的連接埠',
      description: 'URL 使用非標準連接埠',
    },
    credentialsInURL: {
      title: 'URL 中的憑證',
      description: 'URL 包含嵌入的憑證',
    },
    trustedDomain: {
      title: '受信任的網域',
      description: 'URL 指向已知的受信任網域',
    },
    externalURL: {
      title: '外部 URL',
      description: 'Skill 參考外部網域 - 驗證是否預期',
    },
    malformedURL: {
      title: '偵測到格式錯誤的 URL',
      description: '無法解析 URL',
    },
    credentialsInParams: {
      title: 'URL/標頭中的潛在憑證',
      description: '在 URL 參數中發現疑似 API 金鑰或權杖',
    },
    foundURLs: {
      title: '發現外部 URL',
      description: '參考的 URL',
    },
  },

  // PatternScanner
  patterns: {
    promptInjection: {
      title: 'Prompt injection 嘗試',
      description: '包含嘗試覆蓋 AI 指令的語句',
    },
    disregardSafety: {
      title: 'Prompt injection - 忽視安全',
      description: '嘗試讓 AI 忽視安全準則',
    },
    roleManipulation: {
      title: '角色操作嘗試',
      description: '嘗試將 AI 角色變更為特權模式',
    },
    danJailbreak: {
      title: '已知越獄模式 (DAN)',
      description: '包含已知的 AI 越獄模式',
    },
    fakeSystemInstruction: {
      title: '偽造系統指令',
      description: '嘗試注入偽造的系統級指令',
    },
    privateKey: {
      title: '偵測到私鑰',
      description: '包含疑似私鑰的內容',
    },
    pgpPrivateKey: {
      title: '偵測到 PGP 私鑰',
      description: '包含 PGP 私鑰材料',
    },
    awsAccessKey: {
      title: 'AWS Access Key ID',
      description: '包含 AWS 存取金鑰識別碼',
    },
    openaiKey: {
      title: 'OpenAI API 金鑰',
      description: '包含 OpenAI API 金鑰模式',
    },
    anthropicKey: {
      title: 'Anthropic API 金鑰',
      description: '包含 Anthropic API 金鑰模式',
    },
    githubPAT: {
      title: 'GitHub 個人存取權杖',
      description: '包含 GitHub PAT',
    },
    slackToken: {
      title: 'Slack 權杖',
      description: '包含 Slack API 權杖模式',
    },
    apiKeyPair: {
      title: '潛在的 API 金鑰對',
      description: '包含符合 key:secret 格式的模式',
    },
    evalUsage: {
      title: '使用 eval',
      description: '使用可執行任意程式碼的 eval()',
    },
    execUsage: {
      title: '使用 exec',
      description: '使用可執行任意程式碼的 exec()',
    },
    dynamicFunction: {
      title: '動態函數建構',
      description: '從字串建立函數 - 潛在的程式碼注入',
    },
    documentWrite: {
      title: '使用 document.write',
      description: '使用可用於 XSS 的 document.write',
    },
    innerHTML: {
      title: 'innerHTML 賦值',
      description: '直接操作 innerHTML - 潛在的 XSS 向量',
    },
    templateLiterals: {
      title: '模板字面值',
      description: '使用模板字面值 - 驗證無注入點',
    },
    envAccess: {
      title: '環境變數存取',
      description: '存取環境變數',
    },
    childProcess: {
      title: 'Child process 匯入',
      description: '匯入用於 shell 執行的 child_process 模組',
    },
    processSpawn: {
      title: '程序產生函數',
      description: '使用 Node.js 程序產生函數',
    },
    urgencyLanguage: {
      title: '緊急語言',
      description: '包含常用於社交工程的緊急語言',
    },
    trustLanguage: {
      title: '建立信任的語言',
      description: '包含嘗試建立虛假信任的語句',
    },
    authContent: {
      title: '認證相關內容',
      description: '參考認證 - 驗證意圖',
    },
    suspiciousFilename: {
      title: '可疑的檔案名稱',
      description: '發現可疑檔案',
    },
    largeFileCount: {
      title: '大量檔案',
      description: 'Skill 包含許多檔案 - 請仔細審查所有檔案',
    },
    fileCount: {
      title: '檔案數量',
      description: '檔案',
    },
  },

  // DataExfiltrationScanner
  dataExfiltration: {
    readSensitiveCredentials: {
      title: '讀取敏感憑證檔案',
      description: '嘗試讀取環境變數、私鑰或憑證檔案',
    },
    readSensitiveConfig: {
      title: '讀取敏感設定目錄',
      description: '嘗試存取 SSH、GPG、AWS、Kubernetes 或 Docker 設定',
    },
    readSystemAuth: {
      title: '讀取系統認證檔案',
      description: '嘗試讀取系統密碼或權限設定檔',
    },
    findSensitiveFiles: {
      title: '搜尋敏感檔案',
      description: '使用 find 搜尋憑證或秘密檔案',
    },
    grepPasswords: {
      title: '搜尋密碼內容',
      description: '在檔案中搜尋密碼或金鑰關鍵字',
    },
    listSensitiveDirs: {
      title: '列出敏感目錄',
      description: '列出可能包含憑證的目錄內容',
    },
    browserCredentials: {
      title: '存取瀏覽器密碼/Cookie',
      description: '嘗試讀取瀏覽器儲存的登入憑證或 Cookie',
    },
    firefoxDB: {
      title: '存取 Firefox 資料庫',
      description: '嘗試讀取 Firefox 的 SQLite 資料庫',
    },
    chromeConfig: {
      title: '存取 Chrome 設定',
      description: '嘗試讀取 Chrome 瀏覽器設定檔',
    },
    passwordManager: {
      title: '存取密碼管理器',
      description: '嘗試存取密碼管理器的資料',
    },
    shellHistory: {
      title: '讀取 Shell 歷史紀錄',
      description: '嘗試讀取命令歷史，可能包含敏感指令',
    },
    gitCredentials: {
      title: '讀取 Git 憑證',
      description: '嘗試讀取 Git 儲存的認證資訊',
    },
    gitConfig: {
      title: '讀取 Git 設定',
      description: '讀取 Git 設定檔，可能包含使用者資訊',
    },
    databaseFiles: {
      title: '讀取資料庫檔案',
      description: '嘗試讀取本機資料庫檔案',
    },
    sqliteAccess: {
      title: '存取 SQLite 資料庫',
      description: '使用 sqlite3 存取本機資料庫',
    },
    curlSendCommand: {
      title: 'curl 傳送命令輸出',
      description: '使用 curl 將命令執行結果傳送到外部伺服器',
    },
    curlUploadFile: {
      title: 'curl 上傳檔案內容',
      description: '使用 curl 上傳本機檔案到外部伺服器',
    },
    curlFormUpload: {
      title: 'curl 上傳檔案',
      description: '使用 curl form 上傳檔案到外部',
    },
    wgetUploadFile: {
      title: 'wget 上傳檔案',
      description: '使用 wget 上傳檔案到外部伺服器',
    },
    base64Exfil: {
      title: 'Base64 編碼後外洩',
      description: '將資料 base64 編碼後透過 curl 傳送',
    },
    readEncodeExfil: {
      title: '讀取檔案並編碼外洩',
      description: '讀取檔案、編碼後傳送到外部',
    },
    dnsTunnel: {
      title: 'DNS 隧道外洩',
      description: '透過 DNS 查詢將資料外洩（DNS tunneling）',
    },
    digExfil: {
      title: 'DNS 外洩 (dig)',
      description: '使用 dig 進行 DNS 隧道資料外洩',
    },
    netcatSensitiveFile: {
      title: 'Netcat 傳送敏感檔案',
      description: '使用 netcat 直接傳送敏感檔案',
    },
    netcatExfil: {
      title: 'Netcat 資料外洩',
      description: '透過 netcat 將檔案內容傳送到外部',
    },
    mailSendFile: {
      title: '郵件傳送檔案',
      description: '透過郵件將檔案內容傳送出去',
    },
    mailProgram: {
      title: '郵件程式使用',
      description: '偵測到郵件傳送程式，可能用於資料外洩',
    },
    scpUpload: {
      title: 'SCP 上傳敏感檔案',
      description: '使用 SCP 上傳敏感檔案到遠端伺服器',
    },
    ftpUpload: {
      title: 'FTP 上傳',
      description: '使用 FTP 上傳檔案',
    },
    rsyncRemote: {
      title: 'rsync 到遠端',
      description: '使用 rsync 同步檔案到遠端伺服器',
    },
    awsS3Upload: {
      title: 'AWS S3 上傳',
      description: '上傳檔案到 AWS S3',
    },
    gcsUpload: {
      title: 'Google Cloud Storage 上傳',
      description: '上傳檔案到 GCS',
    },
    azureBlobUpload: {
      title: 'Azure Blob 上傳',
      description: '上傳檔案到 Azure Blob Storage',
    },
    readAndSend: {
      title: '讀取並傳送資料',
      description: '讀取檔案內容並直接傳送到網路',
    },
    batchExfil: {
      title: '批量外洩敏感檔案',
      description: '循環讀取並傳送多個敏感檔案',
    },
    findExecExfil: {
      title: 'Find + 外洩組合',
      description: '搜尋檔案並對每個執行外洩操作',
    },
    tarExfil: {
      title: '打包並外洩',
      description: '將多個檔案打包後直接傳送',
    },
    zipExfil: {
      title: '壓縮並上傳',
      description: '壓縮檔案後上傳到外部',
    },
    envExfil: {
      title: '環境變數外洩',
      description: '將所有環境變數傳送到外部',
    },
    printenvExfil: {
      title: 'printenv 外洩',
      description: '列出所有環境變數並傳送',
    },
    sensitiveEnvExfil: {
      title: '敏感環境變數外洩',
      description: '傳送包含敏感資訊的環境變數',
    },
    shellVarExfil: {
      title: 'Shell 變數外洩',
      description: '列出並可能傳送 shell 變數',
    },
    systemInfoExfil: {
      title: '系統資訊外洩',
      description: '收集並傳送系統識別資訊',
    },
    networkConfigExfil: {
      title: '網路設定外洩',
      description: '傳送網路設定資訊',
    },
    processListExfil: {
      title: '程序列表外洩',
      description: '傳送系統程序列表',
    },
    netstatExfil: {
      title: '網路連線外洩',
      description: '傳送系統網路連線資訊',
    },
    lsofExfil: {
      title: '開啟檔案列表外洩',
      description: '傳送系統開啟的檔案列表',
    },
    cronExfil: {
      title: 'Cron 定時外洩',
      description: '設定定時任務持續外洩資料',
    },
    bashrcModify: {
      title: '修改 .bashrc',
      description: '修改 shell 啟動檔，可能植入後門',
    },
    profileModify: {
      title: '修改 .profile',
      description: '修改使用者 profile，可能植入後門',
    },
    enableService: {
      title: '啟用系統服務',
      description: '啟用系統服務，可能用於持久化',
    },
    readSendCombo: {
      title: '讀取+傳送組合',
      description: 'Skill 同時包含檔案讀取和網路傳送指令，可能用於資料外洩',
    },
    fullExfilToolchain: {
      title: '完整外洩工具鏈',
      description: 'Skill 包含讀取、編碼、傳送的完整資料外洩工具鏈',
    },
    multipleSensitivePaths: {
      title: '大量敏感路徑存取',
      description: '偵測到存取多種敏感路徑，高度可疑',
    },
    loopNetworkOps: {
      title: '迴圈網路操作',
      description: '在迴圈中執行網路傳送，可能批量外洩資料',
    },
  },

  // MCPSecurityScanner
  mcpSecurity: {
    detected: {
      title: '偵測到 MCP 設定',
      description: 'Skill 包含 MCP Server 設定，進行安全檢查',
    },
    unofficialServer: {
      title: '非官方 MCP Server',
      description: '使用非 Anthropic 官方的 MCP server，請確認來源可信',
    },
    urlExecution: {
      title: '從 URL 直接執行 MCP',
      description: '直接從 URL 執行 npx，極度危險',
    },
    thirdPartyGithub: {
      title: '第三方 GitHub MCP Server',
      description: '使用第三方 GitHub 上的 MCP server',
    },
    filesystemUnrestricted: {
      title: 'MCP Filesystem 無限制存取',
      description: 'MCP filesystem server 允許存取所有路徑',
    },
    rootAccess: {
      title: 'MCP 存取根目錄或家目錄',
      description: 'MCP server 被授權存取根目錄或整個家目錄',
    },
    shellExecution: {
      title: 'MCP Shell 執行權限',
      description: '偵測到可執行 shell 命令的 MCP server',
    },
    databaseAccess: {
      title: 'MCP 資料庫存取',
      description: 'MCP server 可存取資料庫，確認權限範圍',
    },
    cloudAccess: {
      title: 'MCP 雲端服務存取',
      description: 'MCP server 可存取雲端服務',
    },
    browserAutomation: {
      title: 'MCP 瀏覽器自動化',
      description: 'MCP server 可控制瀏覽器',
    },
    sensitiveEnv: {
      title: 'MCP 環境變數含敏感資訊',
      description: '在 MCP 設定中傳遞敏感環境變數',
    },
    credentialsInConfig: {
      title: 'MCP 設定包含憑證',
      description: 'MCP 設定檔中包含敏感憑證',
    },
    fileNetworkCombo: {
      title: 'MCP 檔案+網路組合',
      description: '同時擁有檔案存取和網路請求能力，可能用於資料外洩',
    },
    shellNetworkCombo: {
      title: 'MCP Shell+網路組合',
      description: 'Shell 執行加網路存取，可下載執行惡意程式',
    },
    nonOfficialServer: {
      title: '非官方 MCP Server',
      description: '使用第三方 MCP server',
    },
  },

  // SSRFScanner
  ssrf: {
    awsGcpMetadata: {
      title: 'AWS/GCP Metadata Endpoint',
      description: '嘗試存取雲端 metadata endpoint，可竊取 IAM 憑證',
    },
    gcpMetadata: {
      title: 'GCP Metadata Endpoint',
      description: '嘗試存取 Google Cloud metadata',
    },
    ecsMetadata: {
      title: 'AWS ECS Metadata',
      description: '嘗試存取 AWS ECS container metadata',
    },
    alibabaMetadata: {
      title: 'Alibaba Cloud Metadata',
      description: '嘗試存取阿里雲 metadata endpoint',
    },
    azureMetadata: {
      title: 'Azure Metadata Endpoint',
      description: '嘗試存取 Azure Instance Metadata Service',
    },
    cloudMetadataPath: {
      title: 'Cloud Metadata Path',
      description: '偵測到雲端 metadata 路徑模式',
    },
    gcpComputeMetadata: {
      title: 'GCP Compute Metadata',
      description: '嘗試存取 GCP compute metadata',
    },
    gcpMetadataHeader: {
      title: 'GCP Metadata Header',
      description: '使用 GCP metadata 請求標頭',
    },
    internalClassA: {
      title: '內部網路存取 (10.x.x.x)',
      description: '嘗試存取 Class A 私有網路',
    },
    internalClassB: {
      title: '內部網路存取 (172.16-31.x.x)',
      description: '嘗試存取 Class B 私有網路',
    },
    internalClassC: {
      title: '內部網路存取 (192.168.x.x)',
      description: '嘗試存取 Class C 私有網路',
    },
    loopbackAccess: {
      title: 'Loopback 存取',
      description: '嘗試存取 loopback 網路',
    },
    zeroAccess: {
      title: '存取 0.0.0.0',
      description: '嘗試存取所有網路介面',
    },
    ipv6Loopback: {
      title: 'IPv6 Loopback',
      description: '嘗試存取 IPv6 loopback',
    },
    localhostAccess: {
      title: 'Localhost 存取',
      description: '存取 localhost，可能是 SSRF',
    },
    internalServicePorts: {
      title: '內部服務端口探測',
      description: '偵測到常見內部服務端口（Redis、MongoDB、PostgreSQL、MySQL、Elasticsearch、Consul 等）',
    },
    remoteManagementPorts: {
      title: '遠端管理端口',
      description: '偵測到 SSH、Telnet、RDP、VNC 端口',
    },
    devPorts: {
      title: '常見開發端口',
      description: '偵測到常見 Web 開發端口',
    },
    hexIP: {
      title: 'SSRF Bypass - Hex IP',
      description: '使用十六進位 IP 繞過過濾',
    },
    decimalIP: {
      title: '可能的十進位 IP',
      description: '大數字可能是十進位 IP 編碼',
    },
    urlEncodingBypass: {
      title: 'URL 編碼繞過',
      description: '使用 URL 編碼嘗試繞過過濾',
    },
    urlAuthorityConfusion: {
      title: 'URL Authority 混淆',
      description: '使用 @ 符號可能進行 URL 混淆攻擊',
    },
    uncPath: {
      title: 'UNC 路徑',
      description: '使用 UNC 路徑可能存取網路共享',
    },
    fileProtocol: {
      title: 'File Protocol',
      description: '使用 file:// 協議讀取本地檔案',
    },
    gopherProtocol: {
      title: 'Gopher Protocol',
      description: 'Gopher 協議常用於 SSRF 攻擊',
    },
    dictProtocol: {
      title: 'Dict Protocol',
      description: 'Dict 協議可用於探測服務',
    },
    ldapProtocol: {
      title: 'LDAP Protocol',
      description: 'LDAP 協議可能導致資訊洩漏',
    },
    k8sInternalService: {
      title: 'Kubernetes 內部服務',
      description: '嘗試存取 Kubernetes 內部服務',
    },
    k8sAPIPath: {
      title: 'Kubernetes API 路徑',
      description: '嘗試存取 Kubernetes API',
    },
    k8sNamespace: {
      title: 'Kubernetes Namespace',
      description: '引用 Kubernetes 系統 namespace',
    },
    k8sAuth: {
      title: 'Kubernetes 認證',
      description: '嘗試存取 Kubernetes 認證資訊',
    },
    dockerSocket: {
      title: 'Docker Socket 存取',
      description: '嘗試存取 Docker socket，可接管主機',
    },
    dockerCommand: {
      title: 'Docker 命令執行',
      description: '執行 Docker 命令',
    },
    dockerPrivileged: {
      title: 'Docker 特權模式',
      description: '使用 Docker 特權模式或增加 capabilities',
    },
    iamCredentials: {
      title: 'AWS IAM 憑證存取',
      description: '嘗試從 metadata 取得 IAM 憑證',
    },
    ec2Identity: {
      title: 'AWS EC2 Identity',
      description: '嘗試取得 EC2 身份憑證',
    },
    imdsv2Token: {
      title: 'AWS IMDSv2 Token',
      description: '偵測 AWS IMDSv2 token 請求',
    },
    networkToolMetadata: {
      title: '網路工具 + Metadata 存取',
      description: 'Skill 包含網路請求工具和雲端 metadata endpoint，高度可疑的 SSRF 攻擊',
    },
    networkToolInternalIP: {
      title: '網路工具 + 內部 IP',
      description: 'Skill 包含網路請求工具和內部 IP 位址，可能探測內部網路',
    },
    dynamicURLConstruction: {
      title: '動態 URL 構造',
      description: '偵測到動態構造 URL 的模式，可能允許 SSRF 注入',
    },
  },

  // DependencyScanner
  dependency: {
    knownMalicious: {
      title: '已知惡意/問題套件',
      description: '偵測到已知問題套件，此套件曾有安全事件或已被廢棄',
    },
    knownMaliciousDep: {
      title: '已知問題依賴',
      description: 'package.json 包含已知問題套件',
    },
    typosquatting: {
      title: '可疑套件名稱',
      description: '可能是拼寫錯誤（typosquatting 攻擊）',
    },
    prereleaseVersion: {
      title: '安裝 prerelease 版本',
      description: '安裝 alpha/beta/rc 版本，可能不穩定或含惡意代碼',
    },
    urlInstall: {
      title: '從 URL 安裝套件',
      description: '直接從 URL 安裝 npm 套件，無法驗證完整性',
    },
    gitInstall: {
      title: '從 Git 安裝套件',
      description: '從 Git 倉庫安裝，可能指向惡意分支',
    },
    ignoreScripts: {
      title: '忽略安裝腳本',
      description: '雖然這是安全措施，但也可能隱藏其他問題',
    },
    forceInstall: {
      title: '強制安裝',
      description: '強制安裝可能覆蓋安全警告',
    },
    modifyRegistry: {
      title: '修改 npm registry',
      description: '更改 npm registry 可能導向惡意鏡像',
    },
    trustedHost: {
      title: 'pip 信任不安全主機',
      description: '信任未驗證的 pip 主機',
    },
    httpIndex: {
      title: 'pip 使用 HTTP index',
      description: '使用不安全的 HTTP 連接安裝套件',
    },
    pipGitInstall: {
      title: 'pip 從 Git 安裝',
      description: '從 Git 安裝 Python 套件',
    },
    postinstallCurl: {
      title: 'Install 腳本下載',
      description: 'package.json install 腳本包含下載操作',
    },
    postinstallWget: {
      title: 'Install 腳本下載',
      description: 'package.json install 腳本包含 wget',
    },
    postinstallEval: {
      title: 'Install 腳本 eval',
      description: 'package.json install 腳本使用 eval',
    },
    postinstallNode: {
      title: 'Install 腳本執行 Node',
      description: 'Install 腳本直接執行 Node 代碼',
    },
    postinstallPython: {
      title: 'Install 腳本執行 Python',
      description: 'Install 腳本執行 Python',
    },
    packageCount: {
      title: '偵測到套件安裝指令',
      description: '套件',
    },
    manyPackages: {
      title: '大量套件安裝',
      description: 'Skill 安裝許多套件，請仔細審查每個套件',
    },
    pipMalicious: {
      title: '已知惡意套件',
      description: '偵測到已知惡意 Python 套件',
    },
  },

  // SubAgentScanner
  subagent: {
    detected: {
      title: '偵測到 Sub-agent 使用',
      description: 'Skill 使用 Task 工具產生 sub-agents',
    },
    bashAgent: {
      title: 'Task 派生 Bash Agent',
      description: 'Sub-agent 嘗試使用 Bash 類型，可執行任意命令',
    },
    opusModel: {
      title: 'Task 使用 Opus 模型',
      description: 'Sub-agent 嘗試使用最強大的模型',
    },
    allowAll: {
      title: 'Task 要求所有權限',
      description: 'Sub-agent 嘗試獲取所有工具權限',
    },
    bashWildcard: {
      title: 'Task 包含 Bash(*)',
      description: 'Sub-agent 嘗試獲取無限制的 Shell 存取',
    },
    promptInjection: {
      title: 'Task Prompt Injection',
      description: 'Sub-agent prompt 包含 prompt injection 嘗試',
    },
    roleEscalation: {
      title: 'Task 角色提升嘗試',
      description: 'Sub-agent prompt 嘗試角色提升',
    },
    bypassVerification: {
      title: 'Task 繞過驗證',
      description: 'Sub-agent prompt 嘗試繞過安全驗證',
    },
    dangerousCommand: {
      title: 'Task 包含危險指令',
      description: 'Sub-agent prompt 包含 curl | bash 等危險指令',
    },
    deleteCommand: {
      title: 'Task 包含刪除指令',
      description: 'Sub-agent prompt 包含遞迴刪除指令',
    },
    nestedTask: {
      title: 'Agent 嵌套呼叫',
      description: 'Sub-agent 嘗試產生更多 sub-agents，可能形成攻擊鏈',
    },
    multipleTask: {
      title: '多重 Task 呼叫',
      description: '偵測到多個 Task 呼叫，檢查是否有協調攻擊',
    },
    taskLoop: {
      title: 'Task 迴圈呼叫',
      description: 'Task 在迴圈中呼叫，可能導致 DoS',
    },
    taskForLoop: {
      title: 'Task for 迴圈',
      description: 'Task 在 for 迴圈中呼叫，可能消耗大量資源',
    },
    taskInterval: {
      title: 'Task 定時重複',
      description: 'Task 被設定為定時重複執行',
    },
    recursiveKeyword: {
      title: '遞迴關鍵字',
      description: '偵測到遞迴相關關鍵字，檢查是否有無限遞迴風險',
    },
    readNetworkCombo: {
      title: 'Task 讀取+網路組合',
      description: 'Sub-agent 同時包含讀取和網路工具，可能用於資料外洩',
    },
    accessSensitiveData: {
      title: 'Task 存取敏感資料',
      description: 'Sub-agent prompt 嘗試存取敏感檔案',
    },
    exploreSensitive: {
      title: 'Explore 敏感區域',
      description: 'Explore agent 嘗試探索敏感目錄',
    },
    backgroundExecution: {
      title: 'Task 背景執行',
      description: 'Sub-agent 要求在背景執行，需注意監控',
    },
    backgroundWithNetwork: {
      title: '背景 Task 含網路/Shell',
      description: '背景執行的 Task 包含網路或 Shell 存取',
    },
    dangerousAgentType: {
      title: '危險 Agent 類型',
      description: '嘗試使用危險的 agent 類型',
    },
    customAgentType: {
      title: '自訂 Agent 類型',
      description: '使用自訂 agent 類型，需審查其能力',
    },
    manyTaskCalls: {
      title: '大量 Task 呼叫',
      description: '偵測到許多 Task 呼叫，請審查每個的必要性',
    },
    tooManyTaskCalls: {
      title: '過多 Task 呼叫',
      description: '偵測到過多 Task 呼叫，可能影響效能或存在濫用',
    },
    nonStandardType: {
      title: '非標準類型',
      description: '使用非標準 agent 類型',
    },
    parallelAgents: {
      title: '平行 Agent 執行',
      description: 'Skill 使用平行 agent 執行，確保資源使用合理',
    },
    dangerousToolCombo: {
      title: '危險工具組合',
      description: 'Sub-agents 使用危險工具組合',
    },
  },
};
