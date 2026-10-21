/**
 * ExternalConnectionScanner - Analyzes URLs, webhooks, and external data flows
 */
export class ExternalConnectionScanner {
  constructor() {
    // Suspicious TLDs often used in malicious activities
    this.suspiciousTLDs = [
      '.tk', '.ml', '.ga', '.cf', '.gq',  // Free domains often abused
      '.xyz', '.top', '.work', '.click',   // Cheap domains common in scams
      '.ru', '.cn', '.su',                 // High-risk country codes
      '.onion'                              // Dark web
    ];

    // Known safe domains
    this.trustedDomains = [
      'github.com',
      'githubusercontent.com',
      'gitlab.com',
      'bitbucket.org',
      'npmjs.com',
      'pypi.org',
      'anthropic.com',
      'openai.com',
      'skillsmp.com'
    ];

    // Suspicious URL patterns
    this.suspiciousUrlPatterns = [
      {
        pattern: /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/gi,
        risk: 'high',
        title: 'Direct IP address URL',
        description: 'URLs pointing directly to IP addresses are often used to bypass domain-based blocking'
      },
      {
        pattern: /https?:\/\/localhost/gi,
        risk: 'medium',
        title: 'Localhost URL reference',
        description: 'References to localhost could indicate debug code or local service exploitation'
      },
      {
        pattern: /https?:\/\/127\.0\.0\.1/gi,
        risk: 'medium',
        title: 'Loopback address URL',
        description: 'References to 127.0.0.1 - similar risk as localhost'
      },
      {
        pattern: /webhook[s]?\.site/gi,
        risk: 'high',
        title: 'Webhook testing service',
        description: 'Webhook.site URLs could be used to exfiltrate data'
      },
      {
        pattern: /requestbin|pipedream\.net|hookbin/gi,
        risk: 'high',
        title: 'Request capture service',
        description: 'Services commonly used to capture and exfiltrate HTTP requests'
      },
      {
        pattern: /ngrok\.io|tunnelto\.dev|localtunnel/gi,
        risk: 'high',
        title: 'Tunnel service URL',
        description: 'Tunneling services could expose internal resources or exfiltrate data'
      },
      {
        pattern: /pastebin\.com|hastebin|ghostbin|paste\./gi,
        risk: 'medium',
        title: 'Paste service URL',
        description: 'Paste services could be used to host malicious payloads'
      },
      {
        pattern: /discord(app)?\.com\/(api\/)?webhooks?\//gi,
        risk: 'high',
        title: 'Discord webhook',
        description: 'Discord webhooks could be used to exfiltrate data'
      },
      {
        pattern: /slack\.com\/api\//gi,
        risk: 'medium',
        title: 'Slack API endpoint',
        description: 'Slack API calls - verify if authorized'
      },
      {
        pattern: /telegram\.org\/bot|api\.telegram/gi,
        risk: 'high',
        title: 'Telegram bot API',
        description: 'Telegram bot API could be used for command and control'
      },
      {
        pattern: /bit\.ly|tinyurl|t\.co|goo\.gl|shorturl/gi,
        risk: 'medium',
        title: 'URL shortener',
        description: 'Shortened URLs hide the actual destination'
      }
    ];

    // Data exfiltration patterns
    this.exfiltrationPatterns = [
      {
        pattern: /curl\s+.{0,300}-d\s+.{0,300}\$\(/gi,
        risk: 'critical',
        title: 'Curl POST with command output',
        description: 'Sending command output to external server'
      },
      {
        pattern: /curl\s+.{0,300}--data.{0,300}\$\{/gi,
        risk: 'critical',
        title: 'Curl data with variable expansion',
        description: 'Sending variable data to external server'
      },
      {
        pattern: /wget\s+.{0,300}--post-data/gi,
        risk: 'high',
        title: 'Wget POST request',
        description: 'Sending data via wget POST'
      },
      {
        pattern: /fetch\s*\([^)]{1,300},\s*\{[^}]{0,300}method:\s*['"]POST/gi,
        risk: 'high',
        title: 'JavaScript fetch POST',
        description: 'Sending data via JavaScript fetch'
      },
      {
        pattern: /XMLHttpRequest|ActiveXObject/gi,
        risk: 'medium',
        title: 'XHR/ActiveX request',
        description: 'Legacy HTTP request methods'
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

    // Extract and analyze all URLs
    const urls = this.extractUrls(content);
    for (const url of urls) {
      this.analyzeUrl(url, findings);
    }

    // Check for suspicious URL patterns
    for (const { pattern, risk, title, description } of this.suspiciousUrlPatterns) {
      const matches = content.match(pattern);
      if (matches) {
        findings[risk].push({
          title,
          description,
          matches: [...new Set(matches)].slice(0, 3),
          scanner: 'ExternalConnectionScanner'
        });
      }
    }

    // Check for data exfiltration patterns
    for (const { pattern, risk, title, description } of this.exfiltrationPatterns) {
      if (pattern.test(content)) {
        findings[risk].push({
          title,
          description,
          scanner: 'ExternalConnectionScanner'
        });
      }
    }

    // Check for hardcoded credentials in URLs
    this.checkCredentialsInUrls(content, findings);

    // Summary of external connections
    if (urls.length > 0) {
      findings.info.push({
        title: `Found ${urls.length} external URL(s)`,
        description: `URLs referenced: ${urls.slice(0, 5).join(', ')}${urls.length > 5 ? '...' : ''}`,
        scanner: 'ExternalConnectionScanner'
      });
    }

    return findings;
  }

  getAllContent(skillContent) {
    let content = skillContent.rawContent || '';
    for (const file of skillContent.files) {
      content += '\n' + file.content;
    }
    return content;
  }

  extractUrls(content) {
    const urlRegex = /https?:\/\/[^\s<>"')\]]{1,300}/gi;
    const matches = content.match(urlRegex) || [];
    return [...new Set(matches)]; // Deduplicate
  }

  analyzeUrl(url, findings) {
    try {
      const urlObj = new URL(url);
      const domain = urlObj.hostname.toLowerCase();

      // Check if trusted
      const isTrusted = this.trustedDomains.some(td =>
        domain === td || domain.endsWith('.' + td)
      );

      if (isTrusted) {
        findings.info.push({
          title: `Trusted domain: ${domain}`,
          description: `URL points to known trusted domain`,
          scanner: 'ExternalConnectionScanner'
        });
        return;
      }

      // Check suspicious TLDs
      for (const tld of this.suspiciousTLDs) {
        if (domain.endsWith(tld)) {
          findings.high.push({
            title: `Suspicious TLD: ${tld}`,
            description: `URL ${url} uses a TLD commonly associated with malicious activity`,
            scanner: 'ExternalConnectionScanner'
          });
          break;
        }
      }

      // Check for suspicious port numbers
      if (urlObj.port && !['80', '443', '8080', '8443'].includes(urlObj.port)) {
        findings.medium.push({
          title: `Unusual port: ${urlObj.port}`,
          description: `URL ${url} uses non-standard port`,
          scanner: 'ExternalConnectionScanner'
        });
      }

      // Check for authentication in URL
      if (urlObj.username || urlObj.password) {
        findings.high.push({
          title: 'Credentials in URL',
          description: `URL contains embedded credentials: ${url}`,
          scanner: 'ExternalConnectionScanner'
        });
      }

      // Generic external URL notice
      findings.low.push({
        title: `External URL: ${domain}`,
        description: `Skill references external domain - verify if expected`,
        scanner: 'ExternalConnectionScanner'
      });

    } catch (e) {
      // Invalid URL
      findings.low.push({
        title: 'Malformed URL detected',
        description: `Could not parse URL: ${url.substring(0, 50)}...`,
        scanner: 'ExternalConnectionScanner'
      });
    }
  }

  checkCredentialsInUrls(content, findings) {
    // API keys in URLs
    const apiKeyPatterns = [
      /[?&](api[_-]?key|apikey|key|token|auth|secret|password)=([^&\s]{1,300})/gi,
      /Authorization:\s*(Bearer|Basic)\s+[A-Za-z0-9+\/=]+/gi
    ];

    for (const pattern of apiKeyPatterns) {
      const matches = content.match(pattern);
      if (matches) {
        findings.high.push({
          title: 'Potential credentials in URL/header',
          description: 'Found what appears to be API keys or tokens in URL parameters',
          matches: matches.map(m => m.substring(0, 30) + '...').slice(0, 2),
          scanner: 'ExternalConnectionScanner'
        });
      }
    }
  }
}
