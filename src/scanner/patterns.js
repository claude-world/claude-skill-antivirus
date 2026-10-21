/**
 * PatternScanner - Detects general suspicious patterns and code smells
 */
export class PatternScanner {
  constructor() {
    // Prompt injection patterns
    this.promptInjectionPatterns = [
      {
        pattern: /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?)/gi,
        risk: 'critical',
        title: 'Prompt injection attempt',
        description: 'Contains phrase attempting to override AI instructions'
      },
      {
        pattern: /disregard\s+(all\s+)?(previous|prior|safety)/gi,
        risk: 'critical',
        title: 'Prompt injection - disregard safety',
        description: 'Attempts to make AI disregard safety guidelines'
      },
      {
        pattern: /you\s+are\s+now\s+(in\s+)?['"](developer|admin|god|root)/gi,
        risk: 'critical',
        title: 'Role manipulation attempt',
        description: 'Attempts to change AI role to privileged mode'
      },
      {
        pattern: /Do\s+Anything\s+Now/gi,
        risk: 'critical',
        title: 'Jailbreak pattern (Do Anything Now)',
        description: 'Contains explicit AI jailbreak phrase'
      },
      {
        pattern: /you\s+are\s+(now\s+)?DAN/gi,
        risk: 'critical',
        title: 'DAN role assignment',
        description: 'Attempts to assign DAN jailbreak role to AI'
      },
      {
        pattern: /\bDAN\s+mode\b|\bact\s+as\s+DAN\b|\benable\s+DAN\b/gi,
        risk: 'critical',
        title: 'DAN mode activation',
        description: 'Attempts to activate DAN jailbreak mode'
      },
      {
        pattern: /\bDAN\b(?=.{0,300}\b(ignore|bypass|override|unlimited|unrestricted)\b)/gi,
        risk: 'high',
        title: 'DAN with bypass keywords',
        description: 'DAN mentioned with security bypass keywords'
      },
      {
        pattern: /system\s*:\s*you\s+(must|should|will)\s+ignore/gi,
        risk: 'high',
        title: 'Fake system instruction',
        description: 'Attempts to inject fake system-level instructions'
      }
    ];

    // Sensitive data patterns
    this.sensitiveDataPatterns = [
      {
        pattern: /-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----/gi,
        risk: 'critical',
        title: 'Private key detected',
        description: 'Contains what appears to be a private key'
      },
      {
        pattern: /-----BEGIN\s+PGP\s+PRIVATE/gi,
        risk: 'critical',
        title: 'PGP private key detected',
        description: 'Contains PGP private key material'
      },
      {
        pattern: /AKIA[0-9A-Z]{16}/gi,
        risk: 'critical',
        title: 'AWS Access Key ID',
        description: 'Contains AWS access key identifier'
      },
      {
        pattern: /sk-[a-zA-Z0-9]{48}/gi,
        risk: 'critical',
        title: 'OpenAI API key',
        description: 'Contains OpenAI API key pattern'
      },
      {
        pattern: /sk-ant-[a-zA-Z0-9-]{80,}/gi,
        risk: 'critical',
        title: 'Anthropic API key',
        description: 'Contains Anthropic API key pattern'
      },
      {
        pattern: /ghp_[a-zA-Z0-9]{36}/gi,
        risk: 'critical',
        title: 'GitHub Personal Access Token',
        description: 'Contains GitHub PAT'
      },
      {
        pattern: /xox[baprs]-[0-9a-zA-Z-]+/gi,
        risk: 'high',
        title: 'Slack token',
        description: 'Contains Slack API token pattern'
      },
      {
        pattern: /[a-f0-9]{32}:[a-f0-9]{32}/gi,
        risk: 'medium',
        title: 'Potential API key pair',
        description: 'Contains pattern matching key:secret format'
      }
    ];

    // Suspicious code patterns
    this.suspiciousCodePatterns = [
      {
        pattern: /eval\s*\(/gi,
        risk: 'high',
        title: 'Eval usage',
        description: 'Uses eval() which can execute arbitrary code'
      },
      {
        pattern: /exec\s*\(/gi,
        risk: 'high',
        title: 'Exec usage',
        description: 'Uses exec() which can execute arbitrary code'
      },
      {
        pattern: /Function\s*\(\s*['"][^'"]{1,300}['"]\s*\)/gi,
        risk: 'high',
        title: 'Dynamic function construction',
        description: 'Creates functions from strings - potential code injection'
      },
      {
        pattern: /document\.write\s*\(/gi,
        risk: 'medium',
        title: 'document.write usage',
        description: 'Uses document.write which can be used for XSS'
      },
      {
        pattern: /innerHTML\s*=/gi,
        risk: 'medium',
        title: 'innerHTML assignment',
        description: 'Direct innerHTML manipulation - potential XSS vector'
      },
      {
        pattern: /\$\{.{0,300}\}/g,
        risk: 'low',
        title: 'Template literals',
        description: 'Uses template literals - verify no injection points',
        minMatches: 5  // Only flag if many instances
      },
      {
        pattern: /process\.env\./gi,
        risk: 'medium',
        title: 'Environment variable access',
        description: 'Accesses environment variables'
      },
      {
        pattern: /require\s*\(\s*['"`]child_process/gi,
        risk: 'high',
        title: 'Child process import',
        description: 'Imports child_process module for shell execution'
      },
      {
        pattern: /spawn|execSync|execFile/gi,
        risk: 'medium',
        title: 'Process spawn functions',
        description: 'Uses Node.js process spawning functions'
      }
    ];

    // Social engineering patterns
    this.socialEngineeringPatterns = [
      {
        pattern: /urgent|immediately|right\s+now|asap/gi,
        risk: 'low',
        title: 'Urgency language',
        description: 'Contains urgency language often used in social engineering'
      },
      {
        pattern: /trust\s+me|don't\s+worry|safe|secure/gi,
        risk: 'low',
        title: 'Trust-building language',
        description: 'Contains phrases attempting to build false trust'
      },
      {
        pattern: /password|credential|login|auth/gi,
        risk: 'low',
        title: 'Authentication-related content',
        description: 'References authentication - verify intent'
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

    const content = this.getAllContent(skillContent);

    // Check prompt injection patterns
    for (const { pattern, risk, title, description } of this.promptInjectionPatterns) {
      const matches = content.match(pattern);
      if (matches) {
        findings[risk].push({
          title,
          description,
          matches: matches.slice(0, 2),
          scanner: 'PatternScanner'
        });
      }
    }

    // Check sensitive data patterns
    for (const { pattern, risk, title, description } of this.sensitiveDataPatterns) {
      const matches = content.match(pattern);
      if (matches) {
        findings[risk].push({
          title,
          description,
          matches: matches.map(m => m.substring(0, 20) + '***').slice(0, 2),
          scanner: 'PatternScanner'
        });
      }
    }

    // Check suspicious code patterns
    for (const { pattern, risk, title, description, minMatches } of this.suspiciousCodePatterns) {
      const matches = content.match(pattern);
      if (matches && (!minMatches || matches.length >= minMatches)) {
        findings[risk].push({
          title,
          description,
          count: matches.length,
          scanner: 'PatternScanner'
        });
      }
    }

    // Check social engineering (only if verbose or combined with other concerns)
    const hasConcerns = findings.critical.length > 0 || findings.high.length > 0;
    if (hasConcerns) {
      for (const { pattern, risk, title, description } of this.socialEngineeringPatterns) {
        const matches = content.match(pattern);
        if (matches && matches.length >= 3) {  // Multiple instances
          findings[risk].push({
            title,
            description,
            count: matches.length,
            scanner: 'PatternScanner'
          });
        }
      }
    }

    // Check file structure
    this.analyzeFileStructure(skillContent, findings);

    return findings;
  }

  getAllContent(skillContent) {
    let content = skillContent.rawContent || '';
    for (const file of skillContent.files) {
      content += '\n' + file.content;
    }
    return content;
  }

  analyzeFileStructure(skillContent, findings) {
    const files = skillContent.files || [];

    // Check for suspicious file names
    const suspiciousNames = [
      { pattern: /backdoor/i, title: 'Suspicious filename: backdoor' },
      { pattern: /hack/i, title: 'Suspicious filename: hack' },
      { pattern: /exploit/i, title: 'Suspicious filename: exploit' },
      { pattern: /payload/i, title: 'Suspicious filename: payload' },
      { pattern: /\.exe$/i, title: 'Windows executable' },
      { pattern: /\.dll$/i, title: 'Windows DLL' },
      { pattern: /\.bat$/i, title: 'Batch file' },
      { pattern: /\.ps1$/i, title: 'PowerShell script' },
      { pattern: /\.vbs$/i, title: 'VBScript file' }
    ];

    for (const file of files) {
      for (const { pattern, title } of suspiciousNames) {
        if (pattern.test(file.name) || pattern.test(file.path)) {
          findings.high.push({
            title,
            description: `Suspicious file found: ${file.path}`,
            scanner: 'PatternScanner'
          });
        }
      }
    }

    // Check file count
    if (files.length > 20) {
      findings.medium.push({
        title: 'Large number of files',
        description: `Skill contains ${files.length} files - review all carefully`,
        scanner: 'PatternScanner'
      });
    }

    // Add file info
    if (files.length > 0) {
      findings.info.push({
        title: `File count: ${files.length}`,
        description: `Files: ${files.map(f => f.name).slice(0, 5).join(', ')}${files.length > 5 ? '...' : ''}`,
        scanner: 'PatternScanner'
      });
    }
  }
}
