/**
 * MCPSecurityScanner - Detects dangerous MCP server configurations
 * Specifically targets MCP Server settings that may pose security risks
 */
export class MCPSecurityScanner {
  constructor() {
    // Untrusted MCP Server sources
    this.untrustedSources = [
      {
        pattern: /npx\s+[^@\s]{0,300}[^/\s](?!@modelcontextprotocol|@anthropic)/gi,
        risk: 'medium',
        title: 'Non-official MCP Server',
        description: 'Using non-Anthropic official MCP server, verify the source is trusted'
      },
      {
        pattern: /npx\s+-y\s+https?:\/\//gi,
        risk: 'critical',
        title: 'Direct URL execution for MCP',
        description: 'Executing npx directly from URL, extremely dangerous'
      },
      {
        pattern: /mcp.{0,300}github\.com\/[^/]{1,300}\/[^/]{1,300}(?!anthropic|modelcontextprotocol)/gi,
        risk: 'medium',
        title: 'Third-party GitHub MCP Server',
        description: 'Using MCP server from third-party GitHub repository'
      }
    ];

    // Dangerous MCP tool permissions
    this.dangerousMCPTools = [
      {
        pattern: /mcp[_-]?filesystem.{0,300}allowed.{0,300}['"]\*['"]/gi,
        risk: 'critical',
        title: 'MCP Filesystem unrestricted access',
        description: 'MCP filesystem server allows access to all paths'
      },
      {
        pattern: /mcp[_-]?filesystem[^}]{0,300}allowedDirectories[^}]{0,300}['"](\/|~)['"]/gi,
        risk: 'critical',
        title: 'MCP access to root or home directory',
        description: 'MCP server authorized to access root directory or entire home directory'
      },
      {
        pattern: /mcp[_-]?(shell|bash|terminal|exec)/gi,
        risk: 'critical',
        title: 'MCP Shell execution permission',
        description: 'Detected MCP server capable of executing shell commands'
      },
      {
        pattern: /mcp[_-]?(postgres|mysql|mongodb|redis|database)/gi,
        risk: 'high',
        title: 'MCP Database access',
        description: 'MCP server can access database, verify permission scope'
      },
      {
        pattern: /mcp[_-]?(aws|gcp|azure|cloud)/gi,
        risk: 'high',
        title: 'MCP Cloud service access',
        description: 'MCP server can access cloud services'
      },
      {
        pattern: /mcp[_-]?puppeteer|mcp[_-]?playwright|mcp[_-]?browser/gi,
        risk: 'medium',
        title: 'MCP Browser automation',
        description: 'MCP server can control browser'
      }
    ];

    // Sensitive environment variables in MCP config
    this.sensitiveEnvPatterns = [
      {
        pattern: /-e\s+[A-Z_]*(?:PASSWORD|SECRET|TOKEN|KEY|CREDENTIAL)[=\s]/gi,
        risk: 'high',
        title: 'MCP environment variable contains sensitive info',
        description: 'Passing sensitive environment variables in MCP configuration'
      },
      {
        pattern: /env['":\s]+\{[^}]{0,300}(?:PASSWORD|SECRET|API_KEY|TOKEN)/gi,
        risk: 'high',
        title: 'MCP config contains credentials',
        description: 'MCP configuration file contains sensitive credentials'
      }
    ];

    // MCP configuration format detection
    this.mcpConfigPatterns = [
      {
        pattern: /["']?mcpServers["']?\s*:/gi,
        isConfig: true,
        title: 'MCP configuration block'
      },
      {
        pattern: /claude\s+mcp\s+add/gi,
        isConfig: true,
        title: 'MCP CLI configuration command'
      },
      {
        pattern: /\.mcp\.json|mcp-config|settings\.json.{0,300}mcp/gi,
        isConfig: true,
        title: 'MCP configuration file'
      }
    ];

    // Known safe official MCP Servers
    this.trustedMCPServers = [
      '@modelcontextprotocol/server-memory',
      '@modelcontextprotocol/server-filesystem',
      '@modelcontextprotocol/server-github',
      '@modelcontextprotocol/server-gitlab',
      '@modelcontextprotocol/server-slack',
      '@modelcontextprotocol/server-puppeteer',
      '@modelcontextprotocol/server-brave-search',
      '@modelcontextprotocol/server-fetch',
      '@modelcontextprotocol/server-postgres',
      '@modelcontextprotocol/server-sqlite',
      '@modelcontextprotocol/server-sequential-thinking',
      '@anthropic/mcp-server',
    ];

    // Dangerous MCP behavior combinations
    this.dangerousCombinations = [
      {
        patterns: [/mcp[_-]?filesystem/gi, /mcp[_-]?fetch|mcp[_-]?http/gi],
        risk: 'critical',
        title: 'MCP Filesystem + Network combination',
        description: 'Has both file access and network request capabilities, may be used for data exfiltration'
      },
      {
        patterns: [/mcp[_-]?shell|mcp[_-]?bash/gi, /mcp[_-]?fetch/gi],
        risk: 'critical',
        title: 'MCP Shell + Network combination',
        description: 'Shell execution plus network access, can download and execute malicious programs'
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

    // Check if contains MCP configuration
    const hasMCPConfig = this.mcpConfigPatterns.some(p => p.pattern.test(content));

    if (!hasMCPConfig) {
      // No MCP configuration, skip scan
      return findings;
    }

    findings.info.push({
      title: 'MCP configuration detected',
      description: 'Skill contains MCP Server configuration, performing security check',
      scanner: 'MCPSecurityScanner'
    });

    // Check untrusted sources
    for (const { pattern, risk, title, description } of this.untrustedSources) {
      const matches = content.match(pattern);
      if (matches) {
        findings[risk].push({
          title,
          description,
          matches: matches.slice(0, 3),
          scanner: 'MCPSecurityScanner'
        });
      }
    }

    // Check dangerous MCP tools
    for (const { pattern, risk, title, description } of this.dangerousMCPTools) {
      const matches = content.match(pattern);
      if (matches) {
        findings[risk].push({
          title,
          description,
          matches: matches.slice(0, 3),
          scanner: 'MCPSecurityScanner'
        });
      }
    }

    // Check sensitive environment variables
    for (const { pattern, risk, title, description } of this.sensitiveEnvPatterns) {
      const matches = content.match(pattern);
      if (matches) {
        findings[risk].push({
          title,
          description,
          matches: matches.map(m => m.substring(0, 30) + '...').slice(0, 2),
          scanner: 'MCPSecurityScanner'
        });
      }
    }

    // Check dangerous combinations
    for (const combo of this.dangerousCombinations) {
      const hasAll = combo.patterns.every(p => p.test(content));
      if (hasAll) {
        findings[combo.risk].push({
          title: combo.title,
          description: combo.description,
          scanner: 'MCPSecurityScanner'
        });
      }
    }

    // Check if using official MCP servers
    this.checkTrustedServers(content, findings);

    return findings;
  }

  getAllContent(skillContent) {
    let content = skillContent.rawContent || '';
    for (const file of skillContent.files) {
      content += '\n' + file.content;
    }
    return content;
  }

  checkTrustedServers(content, findings) {
    // Find all MCP server references
    const serverPatterns = [
      /@[a-z0-9-]+\/[a-z0-9-]+/gi,  // npm scope packages
      /npx\s+([a-z0-9@/-]+)/gi      // npx commands
    ];

    const foundServers = new Set();
    for (const pattern of serverPatterns) {
      const matches = content.match(pattern);
      if (matches) {
        matches.forEach(m => foundServers.add(m.toLowerCase()));
      }
    }

    // Check for non-official servers
    for (const server of foundServers) {
      const isTrusted = this.trustedMCPServers.some(ts =>
        server.includes(ts.toLowerCase())
      );

      if (!isTrusted && server.includes('mcp')) {
        findings.medium.push({
          title: 'Non-official MCP Server',
          description: `Using third-party MCP server: ${server}`,
          scanner: 'MCPSecurityScanner'
        });
      }
    }
  }
}
