/**
 * DangerousCommandScanner - Detects potentially dangerous shell commands and code patterns
 * Identifies destructive commands, privilege escalation, and obfuscation techniques
 */
export class DangerousCommandScanner {
  constructor() {
    // Critical: Commands that can cause severe damage
    this.criticalPatterns = [
      {
        pattern: /rm\s+(-rf?|--recursive)\s+[\/~]/gi,
        title: 'Recursive delete from root/home',
        description: 'Deleting files recursively from root or home directory'
      },
      {
        pattern: /rm\s+(-rf?|--recursive)\s+\*/gi,
        title: 'Recursive delete with wildcard',
        description: 'Deleting files recursively with wildcard pattern'
      },
      {
        pattern: /mkfs\./gi,
        title: 'Filesystem format command',
        description: 'Attempting to format filesystem'
      },
      {
        pattern: /dd\s+if=.{0,300}of=\/dev\//gi,
        title: 'Direct disk write with dd',
        description: 'Writing directly to disk device'
      },
      {
        pattern: /:(){ :|:& };:/g,
        title: 'Fork bomb detected',
        description: 'Classic shell fork bomb pattern'
      },
      {
        pattern: />\s*\/dev\/[sh]da/gi,
        title: 'Direct disk overwrite',
        description: 'Overwriting disk device directly'
      },
      {
        pattern: /chmod\s+(-R\s+)?777\s+\//gi,
        title: 'chmod 777 on root',
        description: 'Setting world-writable permissions on root directory'
      },
      {
        pattern: /curl\s+[^|]{0,300}\|\s*(ba)?sh/gi,
        title: 'curl piped to shell',
        description: 'Downloading and executing remote script'
      },
      {
        pattern: /wget\s+[^|]{0,300}\|\s*(ba)?sh/gi,
        title: 'wget piped to shell',
        description: 'Downloading and executing remote script'
      },
      {
        pattern: /eval\s*\(\s*\$\(/gi,
        title: 'Eval with command substitution',
        description: 'Evaluating dynamic command output'
      }
    ];

    // High: Commands that can expose sensitive data or system
    this.highPatterns = [
      {
        pattern: /cat\s+(\/etc\/passwd|\/etc\/shadow|~\/\.(ssh|gnupg))/gi,
        title: 'Reading sensitive system files',
        description: 'Accessing password, shadow, or SSH/GPG files'
      },
      {
        pattern: /\$\((cat|echo)\s+[^)]{0,300}\.(pem|key|crt)\)/gi,
        title: 'Reading key/certificate files',
        description: 'Accessing private keys or certificates'
      },
      {
        pattern: /export\s+(API_KEY|SECRET|TOKEN|PASSWORD|AWS_|GITHUB_TOKEN)/gi,
        title: 'Environment variable manipulation',
        description: 'Setting sensitive environment variables'
      },
      {
        pattern: /env\s*\|\s*(grep|base64|curl|nc)/gi,
        title: 'Environment variable exfiltration',
        description: 'Sending or encoding environment variables'
      },
      {
        pattern: /nc\s+-[elp]/gi,
        title: 'Netcat listener/reverse shell',
        description: 'Starting netcat listener or connection'
      },
      {
        pattern: /python\s+-c\s+['"]import\s+socket/gi,
        title: 'Python socket connection',
        description: 'Creating network socket via Python'
      },
      {
        pattern: /base64\s+-d.{0,300}\|\s*(ba)?sh/gi,
        title: 'Base64 decode to shell',
        description: 'Decoding and executing base64 content'
      },
      {
        pattern: /ssh\s+-o\s+StrictHostKeyChecking=no/gi,
        title: 'SSH host key check bypass',
        description: 'Connecting to SSH without host key verification'
      },
      {
        pattern: /--no-check-certificate/gi,
        title: 'Certificate check disabled',
        description: 'Skipping SSL/TLS certificate verification'
      },
      {
        pattern: /sudo\s+.{0,300}NOPASSWD/gi,
        title: 'NOPASSWD sudo configuration',
        description: 'Configuring passwordless sudo access'
      }
    ];

    // Medium: Potentially risky patterns
    this.mediumPatterns = [
      {
        pattern: /rm\s+-rf?\s+\S+/gi,
        title: 'Recursive file deletion',
        description: 'Using rm with recursive flag'
      },
      {
        pattern: /chmod\s+(-R\s+)?\d{3,4}\s+/gi,
        title: 'Permission modification',
        description: 'Changing file permissions'
      },
      {
        pattern: /chown\s+(-R\s+)?/gi,
        title: 'Ownership modification',
        description: 'Changing file ownership'
      },
      {
        pattern: /crontab\s+-/gi,
        title: 'Crontab modification',
        description: 'Modifying scheduled tasks'
      },
      {
        pattern: /systemctl\s+(enable|disable|start|stop)/gi,
        title: 'System service control',
        description: 'Controlling system services'
      },
      {
        pattern: /iptables|ufw|firewall-cmd/gi,
        title: 'Firewall modification',
        description: 'Modifying firewall rules'
      },
      {
        pattern: /kill\s+-9/gi,
        title: 'Force kill process',
        description: 'Forcefully terminating process with SIGKILL'
      },
      {
        pattern: /pkill|killall/gi,
        title: 'Kill processes by name',
        description: 'Killing processes by pattern'
      }
    ];

    // Low: Patterns worth noting
    this.lowPatterns = [
      {
        pattern: /sudo\s+/gi,
        title: 'Sudo usage',
        description: 'Using elevated privileges'
      },
      {
        pattern: /npm\s+install\s+-g/gi,
        title: 'Global npm install',
        description: 'Installing npm packages globally'
      },
      {
        pattern: /pip\s+install(?!\s+--user)/gi,
        title: 'System pip install',
        description: 'Installing pip packages system-wide'
      },
      {
        pattern: /git\s+clone/gi,
        title: 'Git clone operation',
        description: 'Cloning remote repository'
      }
    ];
  }

  async scan(skillContent) {
    const findings = {
      critical: [],
      high: [],
      medium: [],
      low: [],
      info: []
    };

    // Scan all file contents
    for (const file of skillContent.files) {
      this.scanContent(file.content, file.path, findings);
    }

    // Also scan raw content
    if (skillContent.rawContent) {
      this.scanContent(skillContent.rawContent, 'SKILL.md', findings);
    }

    return findings;
  }

  scanContent(content, location, findings) {
    // Check critical patterns
    for (const { pattern, title, description } of this.criticalPatterns) {
      const matches = content.match(pattern);
      if (matches) {
        findings.critical.push({
          title,
          description,
          location,
          matches: matches.slice(0, 3),
          scanner: 'DangerousCommandScanner'
        });
      }
    }

    // Check high patterns
    for (const { pattern, title, description } of this.highPatterns) {
      const matches = content.match(pattern);
      if (matches) {
        findings.high.push({
          title,
          description,
          location,
          matches: matches.slice(0, 3),
          scanner: 'DangerousCommandScanner'
        });
      }
    }

    // Check medium patterns
    for (const { pattern, title, description } of this.mediumPatterns) {
      const matches = content.match(pattern);
      if (matches) {
        findings.medium.push({
          title,
          description,
          location,
          matches: matches.slice(0, 3),
          scanner: 'DangerousCommandScanner'
        });
      }
    }

    // Check low patterns
    for (const { pattern, title, description } of this.lowPatterns) {
      const matches = content.match(pattern);
      if (matches) {
        findings.low.push({
          title,
          description,
          location,
          matches: matches.slice(0, 3),
          scanner: 'DangerousCommandScanner'
        });
      }
    }

    // Check for obfuscated code
    this.checkObfuscation(content, location, findings);
  }

  checkObfuscation(content, location, findings) {
    // Check for hex-encoded strings (e.g., \x41\x42\x43\x44)
    const hexPattern = /(\\x[0-9a-f]{2}){4,}/gi;
    if (hexPattern.test(content)) {
      findings.high.push({
        title: 'Hex-encoded content detected',
        description: 'Content contains hex-encoded strings that may hide commands',
        location,
        scanner: 'DangerousCommandScanner'
      });
    }

    // Check for base64 that looks like encoded commands
    const base64Pattern = /[A-Za-z0-9+\/]{50,}={0,2}/g;
    const base64Matches = content.match(base64Pattern);
    if (base64Matches) {
      for (const match of base64Matches.slice(0, 2)) {
        try {
          const decoded = Buffer.from(match, 'base64').toString();
          // Check if decoded content contains shell commands
          if (/\b(sh|bash|curl|wget|rm|chmod)\b/.test(decoded)) {
            findings.high.push({
              title: 'Base64-encoded commands detected',
              description: 'Base64 content decodes to shell commands',
              location,
              scanner: 'DangerousCommandScanner'
            });
            break;
          }
        } catch (e) {
          // Not valid base64, ignore
        }
      }
    }

    // Check for Unicode escapes that could hide commands (e.g., \u0041\u0042\u0043\u0044)
    const unicodePattern = /(\\u[0-9a-f]{4}){4,}/gi;
    if (unicodePattern.test(content)) {
      findings.medium.push({
        title: 'Unicode escape sequences detected',
        description: 'Content contains Unicode escapes that may hide commands',
        location,
        scanner: 'DangerousCommandScanner'
      });
    }
  }
}
