import { checkCompoundPerFile } from './compound.js';

// file:// is an SSRF/local-read attack when handed to a fetcher on the same line,
// or when it targets sensitive system files; a bare mention is reported lower.
const FILE_URL_ATTACK_SOURCE =
  String.raw`(?:fetch|curl|wget|urlopen|requests\.\w+|axios|http\.get|WebFetch|url\s*[:=])[^\n]{0,120}file:\/\/` +
  String.raw`|file:\/\/\/?(?:etc\/(?:passwd|shadow|sudoers|hosts)|proc\/|root\/|home\/[^\s/'"]{1,300}\/\.(?:ssh|aws|gnupg)|~\/\.(?:ssh|aws|gnupg))`;
const FILE_URL_ATTACK = new RegExp(FILE_URL_ATTACK_SOURCE, 'gi');
const FILE_URL_ATTACK_TEST = new RegExp(FILE_URL_ATTACK_SOURCE, 'i');

/**
 * SSRFScanner - Detects Server-Side Request Forgery and cloud attack patterns
 * Identifies SSRF vulnerabilities and cloud infrastructure exploitation attempts
 */
export class SSRFScanner {
  constructor() {
    // Cloud Metadata Endpoints (most dangerous)
    this.cloudMetadataEndpoints = [
      {
        pattern: /169\.254\.169\.254/g,
        risk: 'critical',
        title: 'AWS/GCP Metadata Endpoint',
        description: 'Attempts to access cloud metadata endpoint, can steal IAM credentials'
      },
      {
        pattern: /metadata\.google\.internal/gi,
        risk: 'critical',
        title: 'GCP Metadata Endpoint',
        description: 'Attempts to access Google Cloud metadata'
      },
      {
        pattern: /169\.254\.170\.2/g,
        risk: 'critical',
        title: 'AWS ECS Metadata',
        description: 'Attempts to access AWS ECS container metadata'
      },
      {
        pattern: /100\.100\.100\.200/g,
        risk: 'critical',
        title: 'Alibaba Cloud Metadata',
        description: 'Attempts to access Alibaba Cloud metadata endpoint'
      },
      {
        pattern: /metadata\.azure\.(com|net)/gi,
        risk: 'critical',
        title: 'Azure Metadata Endpoint',
        description: 'Attempts to access Azure Instance Metadata Service'
      },
      {
        pattern: /\/latest\/meta-data|\/latest\/user-data|\/latest\/dynamic/gi,
        risk: 'critical',
        title: 'Cloud Metadata Path',
        description: 'Detected cloud metadata path pattern'
      },
      {
        pattern: /\/computeMetadata\/v1/gi,
        risk: 'critical',
        title: 'GCP Compute Metadata',
        description: 'Attempts to access GCP compute metadata'
      },
      {
        pattern: /Metadata-Flavor:\s*Google/gi,
        risk: 'critical',
        title: 'GCP Metadata Header',
        description: 'Using GCP metadata request header'
      }
    ];

    // Internal network probing
    this.internalNetworkPatterns = [
      {
        pattern: /https?:\/\/10\.\d{1,3}\.\d{1,3}\.\d{1,3}/gi,
        risk: 'high',
        title: 'Internal network access (10.x.x.x)',
        description: 'Attempts to access Class A private network'
      },
      {
        pattern: /https?:\/\/172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}/gi,
        risk: 'high',
        title: 'Internal network access (172.16-31.x.x)',
        description: 'Attempts to access Class B private network'
      },
      {
        pattern: /https?:\/\/192\.168\.\d{1,3}\.\d{1,3}/gi,
        risk: 'high',
        title: 'Internal network access (192.168.x.x)',
        description: 'Attempts to access Class C private network'
      },
      {
        pattern: /https?:\/\/127\.\d{1,3}\.\d{1,3}\.\d{1,3}/gi,
        risk: 'high',
        title: 'Loopback access',
        description: 'Attempts to access loopback network'
      },
      {
        pattern: /https?:\/\/0\.0\.0\.0/gi,
        risk: 'high',
        title: 'Access 0.0.0.0',
        description: 'Attempts to access all network interfaces'
      },
      {
        pattern: /https?:\/\/\[::1?\]/gi,
        risk: 'high',
        title: 'IPv6 Loopback',
        description: 'Attempts to access IPv6 loopback'
      },
      {
        pattern: /https?:\/\/localhost/gi,
        risk: 'medium',
        title: 'Localhost access',
        description: 'Accessing localhost, potential SSRF'
      }
    ];

    // Common internal service ports
    this.internalServicePatterns = [
      {
        pattern: /:\s*(6379|27017|5432|3306|9200|9300|11211|5672|15672|8500|2379)/g,
        risk: 'high',
        title: 'Internal service port probing',
        description: 'Detected common internal service ports (Redis, MongoDB, PostgreSQL, MySQL, Elasticsearch, Consul, etc.)'
      },
      {
        pattern: /:\s*(22|23|3389|5900)/g,
        risk: 'medium',
        title: 'Remote management ports',
        description: 'Detected SSH, Telnet, RDP, VNC ports'
      },
      {
        pattern: /:8080|:8443|:9000|:9090|:3000|:4000|:5000|:8000/g,
        risk: 'low',
        title: 'Common development ports',
        description: 'Detected common web development ports'
      }
    ];

    // SSRF Bypass techniques
    this.ssrfBypassPatterns = [
      {
        pattern: /0x[0-9a-f]+\.[0-9a-f]+\.[0-9a-f]+\.[0-9a-f]+/gi,
        risk: 'critical',
        title: 'SSRF Bypass - Hex IP',
        description: 'Using hexadecimal IP to bypass filtering'
      },
      {
        pattern: /\d{8,10}/g,  // Decimal IP (e.g., 2130706433 = 127.0.0.1)
        risk: 'medium',
        title: 'Possible decimal IP',
        description: 'Large number may be decimal IP encoding'
      },
      {
        pattern: /%2f%2f|%252f|%00/gi,
        risk: 'high',
        title: 'URL encoding bypass',
        description: 'Using URL encoding to attempt filter bypass'
      },
      {
        pattern: /@|#.{0,300}@/g,
        risk: 'medium',
        title: 'URL Authority confusion',
        description: 'Using @ symbol may indicate URL obfuscation attack'
      },
      {
        pattern: /\\\\[a-z0-9.-]+\\/gi,
        risk: 'high',
        title: 'UNC path',
        description: 'Using UNC path may access network shares'
      },
      {
        // file:// fed to a fetcher, or aimed at sensitive system files
        pattern: FILE_URL_ATTACK,
        risk: 'critical',
        title: 'File Protocol',
        description: 'Using file:// protocol to read local files'
      },
      {
        // A plain file:// reference (e.g. an MCP resource URI, a LibreOffice
        // profile path) is common in legitimate code and docs.
        pattern: /file:\/\//gi,
        unless: FILE_URL_ATTACK_TEST,
        risk: 'medium',
        title: 'file:// URL reference',
        description: 'References a file:// URL; verify it is not used to read local files'
      },
      {
        pattern: /gopher:\/\//gi,
        risk: 'critical',
        title: 'Gopher Protocol',
        description: 'Gopher protocol commonly used for SSRF attacks'
      },
      {
        pattern: /dict:\/\//gi,
        risk: 'high',
        title: 'Dict Protocol',
        description: 'Dict protocol can be used for service probing'
      },
      {
        pattern: /ldap:\/\/|ldaps:\/\//gi,
        risk: 'high',
        title: 'LDAP Protocol',
        description: 'LDAP protocol may lead to information disclosure'
      }
    ];

    // Kubernetes specific attacks
    this.kubernetesPatterns = [
      {
        pattern: /kubernetes\.default|\.svc\.cluster\.local/gi,
        risk: 'critical',
        title: 'Kubernetes internal service',
        description: 'Attempts to access Kubernetes internal service'
      },
      {
        pattern: /\/api\/v1\/namespaces|\/apis\//gi,
        risk: 'critical',
        title: 'Kubernetes API path',
        description: 'Attempts to access Kubernetes API'
      },
      {
        pattern: /kube-system|kube-public|default/gi,
        risk: 'medium',
        title: 'Kubernetes Namespace',
        description: 'References Kubernetes system namespace'
      },
      {
        pattern: /serviceaccount|\.kube\/config/gi,
        risk: 'high',
        title: 'Kubernetes authentication',
        description: 'Attempts to access Kubernetes authentication info'
      }
    ];

    // Docker specific attacks
    this.dockerPatterns = [
      {
        pattern: /\/var\/run\/docker\.sock/gi,
        risk: 'critical',
        title: 'Docker Socket access',
        description: 'Attempts to access Docker socket, can take over host'
      },
      {
        pattern: /docker\s+(exec|run|cp)/gi,
        risk: 'high',
        title: 'Docker command execution',
        description: 'Executing Docker commands'
      },
      {
        pattern: /--privileged|--cap-add/gi,
        risk: 'critical',
        title: 'Docker privileged mode',
        description: 'Using Docker privileged mode or adding capabilities'
      }
    ];

    // AWS specific attacks
    this.awsPatterns = [
      {
        pattern: /iam\/security-credentials/gi,
        risk: 'critical',
        title: 'AWS IAM credential access',
        description: 'Attempts to obtain IAM credentials from metadata'
      },
      {
        pattern: /identity-credentials\/ec2/gi,
        risk: 'critical',
        title: 'AWS EC2 Identity',
        description: 'Attempts to obtain EC2 identity credentials'
      },
      {
        pattern: /X-aws-ec2-metadata-token/gi,
        risk: 'high',
        title: 'AWS IMDSv2 Token',
        description: 'Detected AWS IMDSv2 token request'
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

    // Scan all pattern categories
    const allPatternGroups = [
      { name: 'Cloud Metadata', patterns: this.cloudMetadataEndpoints },
      { name: 'Internal Network', patterns: this.internalNetworkPatterns },
      { name: 'Internal Service', patterns: this.internalServicePatterns },
      { name: 'SSRF Bypass', patterns: this.ssrfBypassPatterns },
      { name: 'Kubernetes', patterns: this.kubernetesPatterns },
      { name: 'Docker', patterns: this.dockerPatterns },
      { name: 'AWS', patterns: this.awsPatterns }
    ];

    for (const group of allPatternGroups) {
      for (const { pattern, risk, title, description, unless } of group.patterns) {
        // Skip an entry superseded by a more specific one (avoids double counting)
        if (unless && unless.test(content)) continue;
        // Reset regex lastIndex
        pattern.lastIndex = 0;
        const matches = content.match(pattern);
        if (matches) {
          findings[risk].push({
            title: `[${group.name}] ${title}`,
            description,
            matches: [...new Set(matches)].slice(0, 3),
            category: group.name,
            scanner: 'SSRFScanner'
          });
        }
      }
    }

    // Compound behavior analysis (judged per file; cross-file-only matches downgraded)
    checkCompoundPerFile(skillContent, (c, f) => this.analyzeCompoundBehaviors(c, f), findings);

    return findings;
  }

  getAllContent(skillContent) {
    let content = skillContent.rawContent || '';
    for (const file of skillContent.files) {
      content += '\n' + file.content;
    }
    return content;
  }

  analyzeCompoundBehaviors(content, findings) {
    // Check for network tools + internal IP combination
    const hasNetworkTools = /curl|wget|fetch|http\.get|requests\.|axios|WebFetch/gi.test(content);
    // Full dotted quads only: `10\.\d` alone matched version strings like "3.10.4".
    const hasInternalIP = /\b(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168|127\.\d{1,3})\.\d{1,3}\.\d{1,3}\b/.test(content);
    // Cloud metadata endpoints, not the everyday word "metadata".
    const hasMetadata = /169\.254\.169\.254|169\.254\.170\.2|metadata\.google\.internal|metadata\.azure\.com|\/latest\/meta-data|computeMetadata\/v1/i.test(content);

    if (hasNetworkTools && hasMetadata) {
      findings.critical.push({
        title: '[Behavior Analysis] Network tools + Metadata access',
        description: 'Skill contains network request tools and cloud metadata endpoint, highly suspicious SSRF attack',
        scanner: 'SSRFScanner'
      });
    }

    if (hasNetworkTools && hasInternalIP) {
      findings.high.push({
        title: '[Behavior Analysis] Network tools + Internal IP',
        description: 'Skill contains network request tools and internal IP addresses, may probe internal network',
        scanner: 'SSRFScanner'
      });
    }

    // Check for dynamic URL construction
    const hasDynamicUrl = /\$\{.{0,300}\}.{0,300}https?:|https?:.{0,300}\$\{|url\s*=.{0,300}\+|fetch\s*\([^)]{0,300}\+/gi.test(content);
    if (hasDynamicUrl) {
      findings.medium.push({
        title: '[Behavior Analysis] Dynamic URL construction',
        description: 'Detected dynamic URL construction pattern, may allow SSRF injection',
        scanner: 'SSRFScanner'
      });
    }
  }
}
