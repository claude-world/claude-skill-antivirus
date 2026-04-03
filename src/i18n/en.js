/**
 * English language messages for Claude Skill Antivirus
 */
export const en = {
  // CLI messages
  cli: {
    title: 'Claude Skill Installer v2.1.3',
    fetching: 'Fetching skill content...',
    skillLoaded: 'Skill loaded: {name}',
    startingScan: 'Starting security scan...',
    scanComplete: 'Scan complete (--scan-only mode)',
    installBlocked: 'Installation blocked due to CRITICAL security risks.',
    useAllowHighRisk: 'Use --allow-high-risk to override (not recommended)',
    confirmInstall: 'Skill has {riskLevel} risk level. Continue with installation?',
    installCancelled: 'Installation cancelled by user.',
    installing: 'Installing skill...',
    installedTo: 'Skill installed to: {path}',
    installComplete: 'Installation complete!',
    error: 'Error',
  },

  // Report headers
  report: {
    title: 'SECURITY SCAN REPORT',
    riskLevel: 'Risk Level:',
    score: 'Score:',
    findingsSummary: 'Findings Summary:',
    critical: 'Critical:',
    high: 'High:',
    medium: 'Medium:',
    low: 'Low:',
    info: 'Info:',
    criticalIssues: 'CRITICAL ISSUES:',
    highIssues: 'HIGH RISK ISSUES:',
    mediumIssues: 'MEDIUM ISSUES:',
    lowIssues: 'LOW ISSUES:',
    infoItems: 'INFO:',
    location: 'Location',
  },

  // Risk level names
  riskLevels: {
    CRITICAL: 'CRITICAL',
    HIGH: 'HIGH',
    MEDIUM: 'MEDIUM',
    LOW: 'LOW',
    SAFE: 'SAFE',
  },

  // Recommendations
  recommendations: {
    critical: 'DO NOT INSTALL - This skill contains critical security risks that could harm your system.',
    high: 'Installation not recommended - Review all high-risk findings carefully before proceeding.',
    medium: 'Proceed with caution - Some potentially risky patterns detected.',
    low: 'Generally safe - Minor concerns detected, review before use.',
    safe: 'Safe to install - No significant security concerns detected.',
  },

  // Scanner categories
  categories: {
    dataCollection: 'Data Collection',
    dataExfiltration: 'Data Exfiltration',
    combinedAttack: 'Combined Attack',
    envTheft: 'Env Theft',
    systemRecon: 'System Recon',
    persistence: 'Persistence',
    behaviorAnalysis: 'Behavior Analysis',
    cloudMetadata: 'Cloud Metadata',
    internalNetwork: 'Internal Network',
    internalService: 'Internal Service',
    ssrfBypass: 'SSRF Bypass',
    kubernetes: 'Kubernetes',
    docker: 'Docker',
    aws: 'AWS',
    privilegeEscalation: 'Privilege Escalation',
    dangerousPrompt: 'Dangerous Prompt',
    agentChain: 'Agent Chain',
    dosAttack: 'DoS Attack',
    dataTheft: 'Data Theft',
    background: 'Background',
    untrustedType: 'Untrusted Type',
  },

  // DangerousCommandScanner
  dangerousCommands: {
    recursiveDeleteRoot: {
      title: 'Recursive delete on root/home directory',
      description: 'Command attempts to recursively delete files from root or home directory',
    },
    recursiveDeleteWildcard: {
      title: 'Recursive delete with wildcard',
      description: 'Command uses wildcard with recursive delete - extremely dangerous',
    },
    filesystemFormat: {
      title: 'Filesystem formatting command',
      description: 'Command attempts to format a filesystem',
    },
    directDiskWrite: {
      title: 'Direct disk write',
      description: 'Command writes directly to disk device',
    },
    forkBomb: {
      title: 'Fork bomb detected',
      description: 'Classic fork bomb pattern that can crash the system',
    },
    diskRedirect: {
      title: 'Direct write to disk',
      description: 'Redirecting output directly to disk device',
    },
    worldWritableRoot: {
      title: 'World-writable root permission',
      description: 'Setting dangerous permissions on root filesystem',
    },
    curlPipeShell: {
      title: 'Pipe URL directly to shell',
      description: 'Downloading and executing remote code without verification',
    },
    wgetPipeShell: {
      title: 'Pipe downloaded content to shell',
      description: 'Downloading and executing remote code without verification',
    },
    evalSubstitution: {
      title: 'Eval with command substitution',
      description: 'Dangerous pattern that can execute arbitrary code',
    },
    readSensitiveFiles: {
      title: 'Reading sensitive system files',
      description: 'Attempting to read password files or private keys',
    },
    readCryptoKeys: {
      title: 'Reading cryptographic keys',
      description: 'Attempting to read private keys or certificates',
    },
    envManipulation: {
      title: 'Environment variable manipulation',
      description: 'Setting or exporting sensitive environment variables',
    },
    envExfiltration: {
      title: 'Environment exfiltration attempt',
      description: 'Piping environment variables to potentially leak secrets',
    },
    netcatListener: {
      title: 'Netcat listener/reverse shell',
      description: 'Setting up network listener that could be used for backdoor',
    },
    pythonSocket: {
      title: 'Python socket one-liner',
      description: 'Inline Python network code - often used for reverse shells',
    },
    base64DecodeShell: {
      title: 'Base64 decode to shell',
      description: 'Obfuscated command execution',
    },
    sshSecurityBypass: {
      title: 'SSH security bypass',
      description: 'Disabling SSH host key verification',
    },
    certVerificationDisabled: {
      title: 'Certificate verification disabled',
      description: 'Downloading without verifying SSL certificates',
    },
    passwordlessSudo: {
      title: 'Passwordless sudo configuration',
      description: 'Attempting to configure passwordless sudo access',
    },
    recursiveDelete: {
      title: 'Recursive delete command',
      description: 'Using rm with recursive flag - verify target carefully',
    },
    permissionChange: {
      title: 'Permission modification',
      description: 'Changing file permissions',
    },
    ownershipChange: {
      title: 'Ownership modification',
      description: 'Changing file ownership',
    },
    cronModification: {
      title: 'Cron job modification',
      description: 'Modifying scheduled tasks',
    },
    serviceControl: {
      title: 'System service manipulation',
      description: 'Controlling system services',
    },
    firewallConfig: {
      title: 'Firewall configuration',
      description: 'Modifying firewall rules',
    },
    forceKill: {
      title: 'Force kill command',
      description: 'Forcefully terminating processes',
    },
    bulkKill: {
      title: 'Bulk process termination',
      description: 'Killing multiple processes by name',
    },
    sudoUsage: {
      title: 'Sudo usage',
      description: 'Command requires elevated privileges',
    },
    globalNpmInstall: {
      title: 'Global npm install',
      description: 'Installing npm packages globally',
    },
    systemPipInstall: {
      title: 'System-wide pip install',
      description: 'Installing Python packages system-wide',
    },
    gitClone: {
      title: 'Git clone operation',
      description: 'Cloning a remote repository',
    },
    hexEncoded: {
      title: 'Hex-encoded content detected',
      description: 'Content contains hex-encoded strings that may hide malicious code',
    },
    base64EncodedCommands: {
      title: 'Base64-encoded shell commands',
      description: 'Hidden shell commands found in base64-encoded content',
    },
    unicodeEscape: {
      title: 'Unicode escape sequences detected',
      description: 'Content contains unicode escapes that may obfuscate code',
    },
  },

  // PermissionScanner
  permissions: {
    noExplicitTools: {
      title: 'No explicit tool permissions',
      description: 'Skill does not declare allowed-tools - may use defaults',
    },
    criticalTool: {
      title: 'CRITICAL risk tool',
      description: 'Shell command execution - can run any system command',
    },
    highTool: {
      title: 'HIGH risk tool',
      description: 'High risk tool with potentially dangerous capabilities',
    },
    mediumTool: {
      title: 'MEDIUM risk tool',
      description: 'Medium risk tool with notable access',
    },
    lowTool: {
      title: 'LOW risk tool',
      description: 'Low risk tool with limited capabilities',
    },
    unrestrictedBash: {
      title: 'Unrestricted Bash access',
      description: 'Skill has unrestricted shell access - can execute any command',
    },
    wildcardBash: {
      title: 'Wildcard Bash permissions',
      description: 'Bash permissions use wildcards - overly broad access',
    },
    wildcardPermission: {
      title: 'Wildcard in tool permissions',
      description: 'Wildcards in permissions may grant broader access than necessary',
    },
    dangerousCombination: {
      title: 'Dangerous tool combination detected',
      description: 'Tools combination poses security risk',
    },
    toolCount: {
      title: 'Tool permissions declared',
      description: 'Allowed tools',
    },
    toolDescriptions: {
      Bash: 'Shell command execution - can run any system command',
      'Bash(*)': 'Unrestricted shell access - highest risk',
      Write: 'File writing capability - can modify or create any file',
      Edit: 'File editing capability - can modify existing files',
      Read: 'File reading capability - can access any readable file',
      Glob: 'File discovery - can find files matching patterns',
      Grep: 'Content search - can search file contents',
      WebFetch: 'External HTTP requests - can access internet resources',
      Task: 'Sub-agent spawning - can create autonomous sub-processes',
      Delete: 'File deletion - can remove files and directories',
    },
  },

  // ExternalConnectionScanner
  externalConnections: {
    directIP: {
      title: 'Direct IP address URL',
      description: 'URLs pointing directly to IP addresses are often used to bypass domain-based blocking',
    },
    localhost: {
      title: 'Localhost URL reference',
      description: 'References to localhost could indicate debug code or local service exploitation',
    },
    loopback: {
      title: 'Loopback address URL',
      description: 'References to 127.0.0.1 - similar risk as localhost',
    },
    webhookSite: {
      title: 'Webhook testing service',
      description: 'Webhook.site URLs could be used to exfiltrate data',
    },
    requestCapture: {
      title: 'Request capture service',
      description: 'Services commonly used to capture and exfiltrate HTTP requests',
    },
    tunnelService: {
      title: 'Tunnel service URL',
      description: 'Tunneling services could expose internal resources or exfiltrate data',
    },
    pasteService: {
      title: 'Paste service URL',
      description: 'Paste services could be used to host malicious payloads',
    },
    discordWebhook: {
      title: 'Discord webhook',
      description: 'Discord webhooks could be used to exfiltrate data',
    },
    slackAPI: {
      title: 'Slack API endpoint',
      description: 'Slack API calls - verify if authorized',
    },
    telegramBot: {
      title: 'Telegram bot API',
      description: 'Telegram bot API could be used for command and control',
    },
    urlShortener: {
      title: 'URL shortener',
      description: 'Shortened URLs hide the actual destination',
    },
    curlPostCommand: {
      title: 'Curl POST with command output',
      description: 'Sending command output to external server',
    },
    curlPostVariable: {
      title: 'Curl data with variable expansion',
      description: 'Sending variable data to external server',
    },
    wgetPost: {
      title: 'Wget POST request',
      description: 'Sending data via wget POST',
    },
    fetchPost: {
      title: 'JavaScript fetch POST',
      description: 'Sending data via JavaScript fetch',
    },
    xhrRequest: {
      title: 'XHR/ActiveX request',
      description: 'Legacy HTTP request methods',
    },
    suspiciousTLD: {
      title: 'Suspicious TLD',
      description: 'URL uses a TLD commonly associated with malicious activity',
    },
    unusualPort: {
      title: 'Unusual port',
      description: 'URL uses non-standard port',
    },
    credentialsInURL: {
      title: 'Credentials in URL',
      description: 'URL contains embedded credentials',
    },
    trustedDomain: {
      title: 'Trusted domain',
      description: 'URL points to known trusted domain',
    },
    externalURL: {
      title: 'External URL',
      description: 'Skill references external domain - verify if expected',
    },
    malformedURL: {
      title: 'Malformed URL detected',
      description: 'Could not parse URL',
    },
    credentialsInParams: {
      title: 'Potential credentials in URL/header',
      description: 'Found what appears to be API keys or tokens in URL parameters',
    },
    foundURLs: {
      title: 'Found external URL(s)',
      description: 'URLs referenced',
    },
  },

  // PatternScanner
  patterns: {
    promptInjection: {
      title: 'Prompt injection attempt',
      description: 'Contains phrase attempting to override AI instructions',
    },
    disregardSafety: {
      title: 'Prompt injection - disregard safety',
      description: 'Attempts to make AI disregard safety guidelines',
    },
    roleManipulation: {
      title: 'Role manipulation attempt',
      description: 'Attempts to change AI role to privileged mode',
    },
    danJailbreak: {
      title: 'Known jailbreak pattern (DAN)',
      description: 'Contains known AI jailbreak pattern',
    },
    fakeSystemInstruction: {
      title: 'Fake system instruction',
      description: 'Attempts to inject fake system-level instructions',
    },
    privateKey: {
      title: 'Private key detected',
      description: 'Contains what appears to be a private key',
    },
    pgpPrivateKey: {
      title: 'PGP private key detected',
      description: 'Contains PGP private key material',
    },
    awsAccessKey: {
      title: 'AWS Access Key ID',
      description: 'Contains AWS access key identifier',
    },
    openaiKey: {
      title: 'OpenAI API key',
      description: 'Contains OpenAI API key pattern',
    },
    anthropicKey: {
      title: 'Anthropic API key',
      description: 'Contains Anthropic API key pattern',
    },
    githubPAT: {
      title: 'GitHub Personal Access Token',
      description: 'Contains GitHub PAT',
    },
    slackToken: {
      title: 'Slack token',
      description: 'Contains Slack API token pattern',
    },
    apiKeyPair: {
      title: 'Potential API key pair',
      description: 'Contains pattern matching key:secret format',
    },
    evalUsage: {
      title: 'Eval usage',
      description: 'Uses eval() which can execute arbitrary code',
    },
    execUsage: {
      title: 'Exec usage',
      description: 'Uses exec() which can execute arbitrary code',
    },
    dynamicFunction: {
      title: 'Dynamic function construction',
      description: 'Creates functions from strings - potential code injection',
    },
    documentWrite: {
      title: 'document.write usage',
      description: 'Uses document.write which can be used for XSS',
    },
    innerHTML: {
      title: 'innerHTML assignment',
      description: 'Direct innerHTML manipulation - potential XSS vector',
    },
    templateLiterals: {
      title: 'Template literals',
      description: 'Uses template literals - verify no injection points',
    },
    envAccess: {
      title: 'Environment variable access',
      description: 'Accesses environment variables',
    },
    childProcess: {
      title: 'Child process import',
      description: 'Imports child_process module for shell execution',
    },
    processSpawn: {
      title: 'Process spawn functions',
      description: 'Uses Node.js process spawning functions',
    },
    urgencyLanguage: {
      title: 'Urgency language',
      description: 'Contains urgency language often used in social engineering',
    },
    trustLanguage: {
      title: 'Trust-building language',
      description: 'Contains phrases attempting to build false trust',
    },
    authContent: {
      title: 'Authentication-related content',
      description: 'References authentication - verify intent',
    },
    suspiciousFilename: {
      title: 'Suspicious filename',
      description: 'Suspicious file found',
    },
    largeFileCount: {
      title: 'Large number of files',
      description: 'Skill contains many files - review all carefully',
    },
    fileCount: {
      title: 'File count',
      description: 'Files',
    },
  },

  // DataExfiltrationScanner
  dataExfiltration: {
    readSensitiveCredentials: {
      title: 'Reading sensitive credential files',
      description: 'Attempting to read environment variables, private keys, or certificate files',
    },
    readSensitiveConfig: {
      title: 'Reading sensitive config directories',
      description: 'Attempting to access SSH, GPG, AWS, Kubernetes, or Docker configurations',
    },
    readSystemAuth: {
      title: 'Reading system authentication files',
      description: 'Attempting to read system password or permission configuration files',
    },
    findSensitiveFiles: {
      title: 'Searching for sensitive files',
      description: 'Using find to search for credentials or secret files',
    },
    grepPasswords: {
      title: 'Searching for password content',
      description: 'Searching files for password or key keywords',
    },
    listSensitiveDirs: {
      title: 'Listing sensitive directories',
      description: 'Listing directories that may contain credentials',
    },
    browserCredentials: {
      title: 'Accessing browser passwords/cookies',
      description: 'Attempting to read browser stored login credentials or cookies',
    },
    firefoxDB: {
      title: 'Accessing Firefox database',
      description: 'Attempting to read Firefox SQLite database',
    },
    chromeConfig: {
      title: 'Accessing Chrome config',
      description: 'Attempting to read Chrome browser configuration files',
    },
    passwordManager: {
      title: 'Accessing password manager',
      description: 'Attempting to access password manager data',
    },
    shellHistory: {
      title: 'Reading shell history',
      description: 'Attempting to read command history, may contain sensitive commands',
    },
    gitCredentials: {
      title: 'Reading Git credentials',
      description: 'Attempting to read Git stored authentication information',
    },
    gitConfig: {
      title: 'Reading Git config',
      description: 'Reading Git configuration file, may contain user information',
    },
    databaseFiles: {
      title: 'Reading database files',
      description: 'Attempting to read local database files',
    },
    sqliteAccess: {
      title: 'Accessing SQLite database',
      description: 'Using sqlite3 to access local database',
    },
    curlSendCommand: {
      title: 'Curl sending command output',
      description: 'Using curl to send command execution results to external server',
    },
    curlUploadFile: {
      title: 'Curl uploading file content',
      description: 'Using curl to upload local files to external server',
    },
    curlFormUpload: {
      title: 'Curl form upload',
      description: 'Using curl form to upload files externally',
    },
    wgetUploadFile: {
      title: 'Wget uploading file',
      description: 'Using wget to upload files to external server',
    },
    base64Exfil: {
      title: 'Base64 encoded exfiltration',
      description: 'Base64 encoding data and sending via curl',
    },
    readEncodeExfil: {
      title: 'Read file and encode for exfiltration',
      description: 'Reading files, encoding, and sending externally',
    },
    dnsTunnel: {
      title: 'DNS tunnel exfiltration',
      description: 'Exfiltrating data through DNS queries (DNS tunneling)',
    },
    digExfil: {
      title: 'DNS exfiltration (dig)',
      description: 'Using dig for DNS tunnel data exfiltration',
    },
    netcatSensitiveFile: {
      title: 'Netcat sending sensitive file',
      description: 'Using netcat to directly send sensitive files',
    },
    netcatExfil: {
      title: 'Netcat data exfiltration',
      description: 'Sending file contents to external via netcat',
    },
    mailSendFile: {
      title: 'Mail sending file',
      description: 'Sending file contents via email',
    },
    mailProgram: {
      title: 'Mail program usage',
      description: 'Detected mail sending program, may be used for data exfiltration',
    },
    scpUpload: {
      title: 'SCP uploading sensitive files',
      description: 'Using SCP to upload sensitive files to remote server',
    },
    ftpUpload: {
      title: 'FTP upload',
      description: 'Using FTP to upload files',
    },
    rsyncRemote: {
      title: 'Rsync to remote',
      description: 'Using rsync to sync files to remote server',
    },
    awsS3Upload: {
      title: 'AWS S3 upload',
      description: 'Uploading files to AWS S3',
    },
    gcsUpload: {
      title: 'Google Cloud Storage upload',
      description: 'Uploading files to GCS',
    },
    azureBlobUpload: {
      title: 'Azure Blob upload',
      description: 'Uploading files to Azure Blob Storage',
    },
    readAndSend: {
      title: 'Read and send data',
      description: 'Reading file contents and sending directly to network',
    },
    batchExfil: {
      title: 'Batch exfiltration of sensitive files',
      description: 'Loop reading and sending multiple sensitive files',
    },
    findExecExfil: {
      title: 'Find + exfiltration combination',
      description: 'Searching files and executing exfiltration on each',
    },
    tarExfil: {
      title: 'Pack and exfiltrate',
      description: 'Packing multiple files and sending directly',
    },
    zipExfil: {
      title: 'Compress and upload',
      description: 'Compressing files and uploading externally',
    },
    envExfil: {
      title: 'Environment variable exfiltration',
      description: 'Sending all environment variables externally',
    },
    printenvExfil: {
      title: 'Printenv exfiltration',
      description: 'Listing all environment variables and sending',
    },
    sensitiveEnvExfil: {
      title: 'Sensitive environment variable exfiltration',
      description: 'Sending environment variables containing sensitive information',
    },
    shellVarExfil: {
      title: 'Shell variable exfiltration',
      description: 'Listing and possibly sending shell variables',
    },
    systemInfoExfil: {
      title: 'System information exfiltration',
      description: 'Collecting and sending system identification information',
    },
    networkConfigExfil: {
      title: 'Network config exfiltration',
      description: 'Sending network configuration information',
    },
    processListExfil: {
      title: 'Process list exfiltration',
      description: 'Sending system process list',
    },
    netstatExfil: {
      title: 'Network connection exfiltration',
      description: 'Sending system network connection information',
    },
    lsofExfil: {
      title: 'Open file list exfiltration',
      description: 'Sending list of system open files',
    },
    cronExfil: {
      title: 'Cron scheduled exfiltration',
      description: 'Setting up scheduled task for continuous data exfiltration',
    },
    bashrcModify: {
      title: 'Modifying .bashrc',
      description: 'Modifying shell startup file, may plant backdoor',
    },
    profileModify: {
      title: 'Modifying .profile',
      description: 'Modifying user profile, may plant backdoor',
    },
    enableService: {
      title: 'Enabling system service',
      description: 'Enabling system service, may be used for persistence',
    },
    readSendCombo: {
      title: 'Read + send combination',
      description: 'Skill contains both file reading and network sending commands, may be used for data exfiltration',
    },
    fullExfilToolchain: {
      title: 'Full exfiltration toolchain',
      description: 'Skill contains complete data exfiltration toolchain: read, encode, send',
    },
    multipleSensitivePaths: {
      title: 'Multiple sensitive path access',
      description: 'Detected access to multiple sensitive paths, highly suspicious',
    },
    loopNetworkOps: {
      title: 'Loop network operations',
      description: 'Executing network sends in loop, may batch exfiltrate data',
    },
  },

  // MCPSecurityScanner
  mcpSecurity: {
    detected: {
      title: 'MCP configuration detected',
      description: 'Skill contains MCP Server configuration, performing security check',
    },
    unofficialServer: {
      title: 'Unofficial MCP Server',
      description: 'Using non-Anthropic official MCP server, verify source is trusted',
    },
    urlExecution: {
      title: 'MCP execution from URL',
      description: 'Executing npx directly from URL, extremely dangerous',
    },
    thirdPartyGithub: {
      title: 'Third-party GitHub MCP Server',
      description: 'Using third-party MCP server from GitHub',
    },
    filesystemUnrestricted: {
      title: 'MCP Filesystem unrestricted access',
      description: 'MCP filesystem server allows access to all paths',
    },
    rootAccess: {
      title: 'MCP accessing root or home directory',
      description: 'MCP server authorized to access root directory or entire home directory',
    },
    shellExecution: {
      title: 'MCP Shell execution permission',
      description: 'Detected MCP server that can execute shell commands',
    },
    databaseAccess: {
      title: 'MCP database access',
      description: 'MCP server can access database, verify permission scope',
    },
    cloudAccess: {
      title: 'MCP cloud service access',
      description: 'MCP server can access cloud services',
    },
    browserAutomation: {
      title: 'MCP browser automation',
      description: 'MCP server can control browser',
    },
    sensitiveEnv: {
      title: 'MCP environment variable contains sensitive info',
      description: 'Passing sensitive environment variables in MCP configuration',
    },
    credentialsInConfig: {
      title: 'MCP configuration contains credentials',
      description: 'MCP configuration file contains sensitive credentials',
    },
    fileNetworkCombo: {
      title: 'MCP file + network combination',
      description: 'Having both file access and network request capabilities, may be used for data exfiltration',
    },
    shellNetworkCombo: {
      title: 'MCP shell + network combination',
      description: 'Shell execution plus network access, can download and execute malicious programs',
    },
    nonOfficialServer: {
      title: 'Non-official MCP Server',
      description: 'Using third-party MCP server',
    },
  },

  // SSRFScanner
  ssrf: {
    awsGcpMetadata: {
      title: 'AWS/GCP Metadata Endpoint',
      description: 'Attempting to access cloud metadata endpoint, can steal IAM credentials',
    },
    gcpMetadata: {
      title: 'GCP Metadata Endpoint',
      description: 'Attempting to access Google Cloud metadata',
    },
    ecsMetadata: {
      title: 'AWS ECS Metadata',
      description: 'Attempting to access AWS ECS container metadata',
    },
    alibabaMetadata: {
      title: 'Alibaba Cloud Metadata',
      description: 'Attempting to access Alibaba Cloud metadata endpoint',
    },
    azureMetadata: {
      title: 'Azure Metadata Endpoint',
      description: 'Attempting to access Azure Instance Metadata Service',
    },
    cloudMetadataPath: {
      title: 'Cloud Metadata Path',
      description: 'Detected cloud metadata path pattern',
    },
    gcpComputeMetadata: {
      title: 'GCP Compute Metadata',
      description: 'Attempting to access GCP compute metadata',
    },
    gcpMetadataHeader: {
      title: 'GCP Metadata Header',
      description: 'Using GCP metadata request header',
    },
    internalClassA: {
      title: 'Internal network access (10.x.x.x)',
      description: 'Attempting to access Class A private network',
    },
    internalClassB: {
      title: 'Internal network access (172.16-31.x.x)',
      description: 'Attempting to access Class B private network',
    },
    internalClassC: {
      title: 'Internal network access (192.168.x.x)',
      description: 'Attempting to access Class C private network',
    },
    loopbackAccess: {
      title: 'Loopback access',
      description: 'Attempting to access loopback network',
    },
    zeroAccess: {
      title: 'Access 0.0.0.0',
      description: 'Attempting to access all network interfaces',
    },
    ipv6Loopback: {
      title: 'IPv6 Loopback',
      description: 'Attempting to access IPv6 loopback',
    },
    localhostAccess: {
      title: 'Localhost access',
      description: 'Accessing localhost, may be SSRF',
    },
    internalServicePorts: {
      title: 'Internal service port probing',
      description: 'Detected common internal service ports (Redis, MongoDB, PostgreSQL, MySQL, Elasticsearch, Consul, etc.)',
    },
    remoteManagementPorts: {
      title: 'Remote management ports',
      description: 'Detected SSH, Telnet, RDP, VNC ports',
    },
    devPorts: {
      title: 'Common development ports',
      description: 'Detected common web development ports',
    },
    hexIP: {
      title: 'SSRF Bypass - Hex IP',
      description: 'Using hexadecimal IP to bypass filtering',
    },
    decimalIP: {
      title: 'Possible decimal IP',
      description: 'Large number may be decimal IP encoding',
    },
    urlEncodingBypass: {
      title: 'URL encoding bypass',
      description: 'Using URL encoding to attempt filter bypass',
    },
    urlAuthorityConfusion: {
      title: 'URL Authority confusion',
      description: 'Using @ symbol may perform URL confusion attack',
    },
    uncPath: {
      title: 'UNC path',
      description: 'Using UNC path may access network shares',
    },
    fileProtocol: {
      title: 'File Protocol',
      description: 'Using file:// protocol to read local files',
    },
    gopherProtocol: {
      title: 'Gopher Protocol',
      description: 'Gopher protocol commonly used in SSRF attacks',
    },
    dictProtocol: {
      title: 'Dict Protocol',
      description: 'Dict protocol can be used to probe services',
    },
    ldapProtocol: {
      title: 'LDAP Protocol',
      description: 'LDAP protocol may lead to information disclosure',
    },
    k8sInternalService: {
      title: 'Kubernetes internal service',
      description: 'Attempting to access Kubernetes internal service',
    },
    k8sAPIPath: {
      title: 'Kubernetes API path',
      description: 'Attempting to access Kubernetes API',
    },
    k8sNamespace: {
      title: 'Kubernetes Namespace',
      description: 'Referencing Kubernetes system namespace',
    },
    k8sAuth: {
      title: 'Kubernetes authentication',
      description: 'Attempting to access Kubernetes authentication information',
    },
    dockerSocket: {
      title: 'Docker Socket access',
      description: 'Attempting to access Docker socket, can take over host',
    },
    dockerCommand: {
      title: 'Docker command execution',
      description: 'Executing Docker commands',
    },
    dockerPrivileged: {
      title: 'Docker privileged mode',
      description: 'Using Docker privileged mode or adding capabilities',
    },
    iamCredentials: {
      title: 'AWS IAM credentials access',
      description: 'Attempting to get IAM credentials from metadata',
    },
    ec2Identity: {
      title: 'AWS EC2 Identity',
      description: 'Attempting to get EC2 identity credentials',
    },
    imdsv2Token: {
      title: 'AWS IMDSv2 Token',
      description: 'Detected AWS IMDSv2 token request',
    },
    networkToolMetadata: {
      title: 'Network tool + Metadata access',
      description: 'Skill contains network request tools and cloud metadata endpoint, highly suspicious SSRF attack',
    },
    networkToolInternalIP: {
      title: 'Network tool + Internal IP',
      description: 'Skill contains network request tools and internal IP addresses, may probe internal network',
    },
    dynamicURLConstruction: {
      title: 'Dynamic URL construction',
      description: 'Detected dynamic URL construction pattern, may allow SSRF injection',
    },
  },

  // DependencyScanner
  dependency: {
    knownMalicious: {
      title: 'Known malicious/problematic package',
      description: 'Detected known problematic package, this package has had security incidents or has been deprecated',
    },
    knownMaliciousDep: {
      title: 'Known problematic dependency',
      description: 'package.json contains known problematic package',
    },
    typosquatting: {
      title: 'Suspicious package name',
      description: 'may be a typo of (typosquatting attack)',
    },
    prereleaseVersion: {
      title: 'Installing prerelease version',
      description: 'Installing alpha/beta/rc version, may be unstable or contain malicious code',
    },
    urlInstall: {
      title: 'Installing package from URL',
      description: 'Installing npm package directly from URL, cannot verify integrity',
    },
    gitInstall: {
      title: 'Installing package from Git',
      description: 'Installing from Git repository, may point to malicious branch',
    },
    ignoreScripts: {
      title: 'Ignoring install scripts',
      description: 'While this is a security measure, it may also hide other issues',
    },
    forceInstall: {
      title: 'Force install',
      description: 'Force install may override security warnings',
    },
    modifyRegistry: {
      title: 'Modifying npm registry',
      description: 'Changing npm registry may redirect to malicious mirror',
    },
    trustedHost: {
      title: 'pip trusting insecure host',
      description: 'Trusting unverified pip host',
    },
    httpIndex: {
      title: 'pip using HTTP index',
      description: 'Using insecure HTTP connection to install packages',
    },
    pipGitInstall: {
      title: 'pip installing from Git',
      description: 'Installing Python package from Git',
    },
    postinstallCurl: {
      title: 'Install script download',
      description: 'package.json install script contains download operation',
    },
    postinstallWget: {
      title: 'Install script wget',
      description: 'package.json install script contains wget',
    },
    postinstallEval: {
      title: 'Install script eval',
      description: 'package.json install script uses eval',
    },
    postinstallNode: {
      title: 'Install script executing Node',
      description: 'Install script directly executes Node code',
    },
    postinstallPython: {
      title: 'Install script executing Python',
      description: 'Install script executes Python',
    },
    packageCount: {
      title: 'Detected package install commands',
      description: 'Packages',
    },
    manyPackages: {
      title: 'Many packages being installed',
      description: 'Skill installs many packages, please review each package carefully',
    },
    pipMalicious: {
      title: 'Known malicious package',
      description: 'Detected known malicious Python package',
    },
  },

  // SubAgentScanner
  subagent: {
    detected: {
      title: 'Sub-agent usage detected',
      description: 'Skill uses Task tool to spawn sub-agents',
    },
    bashAgent: {
      title: 'Task spawning Bash Agent',
      description: 'Sub-agent attempting to use Bash type, can execute arbitrary commands',
    },
    opusModel: {
      title: 'Task using Opus model',
      description: 'Sub-agent attempting to use most powerful model',
    },
    allowAll: {
      title: 'Task requesting all permissions',
      description: 'Sub-agent attempting to obtain all tool permissions',
    },
    bashWildcard: {
      title: 'Task contains Bash(*)',
      description: 'Sub-agent attempting to obtain unrestricted shell access',
    },
    promptInjection: {
      title: 'Task Prompt Injection',
      description: 'Sub-agent prompt contains prompt injection attempt',
    },
    roleEscalation: {
      title: 'Task role escalation attempt',
      description: 'Sub-agent prompt attempting role escalation',
    },
    bypassVerification: {
      title: 'Task bypassing verification',
      description: 'Sub-agent prompt attempting to bypass security verification',
    },
    dangerousCommand: {
      title: 'Task contains dangerous command',
      description: 'Sub-agent prompt contains dangerous commands like curl | bash',
    },
    deleteCommand: {
      title: 'Task contains delete command',
      description: 'Sub-agent prompt contains recursive delete command',
    },
    nestedTask: {
      title: 'Agent nested call',
      description: 'Sub-agent attempting to spawn more sub-agents, may form attack chain',
    },
    multipleTask: {
      title: 'Multiple Task calls',
      description: 'Detected multiple Task calls, check for coordinated attack',
    },
    taskLoop: {
      title: 'Task loop call',
      description: 'Task called in loop, may cause DoS',
    },
    taskForLoop: {
      title: 'Task for loop',
      description: 'Task called in for loop, may consume excessive resources',
    },
    taskInterval: {
      title: 'Task repeated on interval',
      description: 'Task set to repeat on interval',
    },
    recursiveKeyword: {
      title: 'Recursive keyword',
      description: 'Detected recursion-related keywords, check for infinite recursion risk',
    },
    readNetworkCombo: {
      title: 'Task read + network combination',
      description: 'Sub-agent contains both read and network tools, may be used for data exfiltration',
    },
    accessSensitiveData: {
      title: 'Task accessing sensitive data',
      description: 'Sub-agent prompt attempting to access sensitive files',
    },
    exploreSensitive: {
      title: 'Explore sensitive area',
      description: 'Explore agent attempting to explore sensitive directories',
    },
    backgroundExecution: {
      title: 'Task background execution',
      description: 'Sub-agent requesting background execution, monitor closely',
    },
    backgroundWithNetwork: {
      title: 'Background Task with network/shell',
      description: 'Background Task contains network or shell access',
    },
    dangerousAgentType: {
      title: 'Dangerous agent type',
      description: 'Attempting to use dangerous agent type',
    },
    customAgentType: {
      title: 'Custom agent type',
      description: 'Using custom agent type, review its capabilities',
    },
    manyTaskCalls: {
      title: 'Many Task calls',
      description: 'Detected many Task calls, review necessity of each',
    },
    tooManyTaskCalls: {
      title: 'Too many Task calls',
      description: 'Detected too many Task calls, may affect performance or indicate abuse',
    },
    nonStandardType: {
      title: 'Non-standard type',
      description: 'Using non-standard agent type',
    },
    parallelAgents: {
      title: 'Parallel agent execution',
      description: 'Skill uses parallel agent execution, ensure reasonable resource usage',
    },
    dangerousToolCombo: {
      title: 'Dangerous tool combination',
      description: 'Sub-agents use dangerous tool combinations',
    },
  },
};
