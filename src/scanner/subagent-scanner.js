/**
 * SubAgentScanner - Detects malicious sub-agent patterns and Task tool abuse
 * Identifies dangerous Task tool usage, privilege escalation, and agent chain attacks
 */
export class SubAgentScanner {
  constructor() {
    // Dangerous agent privilege escalation attempts
    this.privilegeEscalationPatterns = [
      {
        pattern: /Task\s*\([^)]{0,300}subagent_type\s*[=:]\s*['"]?Bash['"]?/gi,
        risk: 'high',
        title: 'Task spawning Bash Agent',
        description: 'Sub-agent attempts to use Bash type, can execute arbitrary commands'
      },
      {
        pattern: /Task\s*\([^)]{0,300}model\s*[=:]\s*['"]?opus['"]?/gi,
        risk: 'medium',
        title: 'Task using Opus model',
        description: 'Sub-agent attempts to use the most powerful model'
      },
      {
        pattern: /Task\s*\([^)]{0,300}allow[_-]?all/gi,
        risk: 'critical',
        title: 'Task requesting all permissions',
        description: 'Sub-agent attempts to obtain all tool permissions'
      },
      {
        pattern: /Task\s*\([^)]{0,300}Bash\s*\(\s*\*\s*\)/gi,
        risk: 'critical',
        title: 'Task contains Bash(*)',
        description: 'Sub-agent attempts to obtain unrestricted Shell access'
      }
    ];

    // Dangerous agent prompt content
    this.dangerousPromptPatterns = [
      {
        pattern: /Task\s*\([^)]{0,300}prompt\s*[=:][^)]{0,300}ignore\s+(previous|all|safety)/gi,
        risk: 'critical',
        title: 'Task Prompt Injection',
        description: 'Sub-agent prompt contains prompt injection attempt'
      },
      {
        pattern: /Task\s*\([^)]{0,300}prompt\s*[=:][^)]{0,300}you\s+are\s+(now\s+)?in\s+['"]?(god|admin|developer|root)/gi,
        risk: 'critical',
        title: 'Task role elevation attempt',
        description: 'Sub-agent prompt attempts role elevation'
      },
      {
        pattern: /Task\s*\([^)]{0,300}prompt\s*[=:][^)]{0,300}execute.{0,300}without.{0,300}verification/gi,
        risk: 'critical',
        title: 'Task bypassing verification',
        description: 'Sub-agent prompt attempts to bypass security verification'
      },
      {
        pattern: /Task\s*\([^)]{0,300}prompt\s*[=:][^)]{0,300}curl\s+.{0,300}\|\s*bash/gi,
        risk: 'critical',
        title: 'Task contains dangerous command',
        description: 'Sub-agent prompt contains curl | bash and other dangerous commands'
      },
      {
        pattern: /Task\s*\([^)]{0,300}prompt\s*[=:][^)]{0,300}rm\s+-rf/gi,
        risk: 'critical',
        title: 'Task contains delete command',
        description: 'Sub-agent prompt contains recursive delete command'
      }
    ];

    // Agent chain attack patterns
    this.agentChainPatterns = [
      {
        pattern: /Task\s*\([^)]{0,300}prompt\s*[=:][^)]{0,300}Task\s*\(/gi,
        risk: 'high',
        title: 'Agent nested calls',
        description: 'Sub-agent attempts to spawn more sub-agents, may form attack chain'
      },
      {
        pattern: /(Task\s*\()[^)]{0,300}\){2,}/gi,
        risk: 'medium',
        title: 'Multiple Task calls',
        description: 'Detected multiple Task calls, check for coordinated attack'
      }
    ];

    // Loop/DoS attack patterns
    this.dosPatterns = [
      {
        pattern: /while\s*\([^)]{0,300}\)\s*\{[^}]{0,300}Task\s*\(/gi,
        risk: 'critical',
        title: 'Task loop call',
        description: 'Task called in while loop, may cause DoS'
      },
      {
        pattern: /for\s*\([^)]{0,300}\)\s*\{[^}]{0,300}Task\s*\(/gi,
        risk: 'high',
        title: 'Task for loop',
        description: 'Task called in for loop, may consume large resources'
      },
      {
        pattern: /setInterval\s*\([^)]{0,300}Task/gi,
        risk: 'critical',
        title: 'Task scheduled repeat',
        description: 'Task set to execute repeatedly at intervals'
      },
      {
        pattern: /recursive|recursion/gi,
        risk: 'medium',
        title: 'Recursion keyword',
        description: 'Detected recursion-related keywords, check for infinite recursion risk'
      }
    ];

    // Data theft agent patterns
    this.dataTheftAgentPatterns = [
      {
        pattern: /Task\s*\([^)]{0,300}(?:Read|Glob|Grep)[^)]{0,300}(?:WebFetch|curl|http)/gi,
        risk: 'critical',
        title: 'Task Read + Network combination',
        description: 'Sub-agent contains both read and network tools, may be used for data exfiltration'
      },
      {
        pattern: /Task\s*\([^)]{0,300}prompt\s*[=:][^)]{0,300}(\.env|\.ssh|\.aws|credential|secret|password)/gi,
        risk: 'critical',
        title: 'Task accessing sensitive data',
        description: 'Sub-agent prompt attempts to access sensitive files'
      },
      {
        pattern: /Task\s*\([^)]{0,300}Explore[^)]{0,300}(?:ssh|aws|credential|secret|password|\.env)/gi,
        risk: 'high',
        title: 'Explore sensitive areas',
        description: 'Explore agent attempts to explore sensitive directories'
      }
    ];

    // Background execution risks
    this.backgroundPatterns = [
      {
        pattern: /Task\s*\([^)]{0,300}run[_-]?in[_-]?background\s*[=:]\s*true/gi,
        risk: 'medium',
        title: 'Task background execution',
        description: 'Sub-agent requests background execution, needs monitoring'
      },
      {
        pattern: /Task\s*\([^)]{0,300}background[^)]{0,300}(?:curl|wget|nc|bash)/gi,
        risk: 'high',
        title: 'Background Task with Network/Shell',
        description: 'Background Task contains network or Shell access'
      }
    ];

    // Untrusted agent types
    this.untrustedAgentTypes = [
      {
        pattern: /subagent_type\s*[=:]\s*['"]?(?:shell|terminal|exec|admin|root)['"]?/gi,
        risk: 'critical',
        title: 'Dangerous agent type',
        description: 'Attempting to use dangerous agent type'
      },
      {
        pattern: /subagent_type\s*[=:]\s*['"]?(?:custom|unknown|generic)['"]?/gi,
        risk: 'medium',
        title: 'Custom agent type',
        description: 'Using custom agent type, review its capabilities'
      }
    ];

    // Claude Code specific agent types
    this.knownAgentTypes = [
      'Explore', 'Plan', 'Bash', 'code-reviewer', 'debugger',
      'test-runner', 'doc-writer', 'security-auditor', 'general-purpose'
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

    // Check if Task/Sub-agent is used
    const hasTask = /Task\s*\(|subagent|sub[_-]?agent/gi.test(content);

    if (!hasTask) {
      return findings;  // No Task usage, skip scan
    }

    findings.info.push({
      title: 'Sub-agent usage detected',
      description: 'Skill uses Task tool to spawn sub-agents',
      scanner: 'SubAgentScanner'
    });

    // Scan all patterns
    const allPatternGroups = [
      { name: 'Privilege Escalation', patterns: this.privilegeEscalationPatterns },
      { name: 'Dangerous Prompt', patterns: this.dangerousPromptPatterns },
      { name: 'Agent Chain', patterns: this.agentChainPatterns },
      { name: 'DoS Attack', patterns: this.dosPatterns },
      { name: 'Data Theft', patterns: this.dataTheftAgentPatterns },
      { name: 'Background Execution', patterns: this.backgroundPatterns },
      { name: 'Untrusted Type', patterns: this.untrustedAgentTypes }
    ];

    for (const group of allPatternGroups) {
      for (const { pattern, risk, title, description } of group.patterns) {
        // Reset regex
        pattern.lastIndex = 0;
        const matches = content.match(pattern);
        if (matches) {
          findings[risk].push({
            title: `[${group.name}] ${title}`,
            description,
            matches: matches.slice(0, 3),
            category: group.name,
            scanner: 'SubAgentScanner'
          });
        }
      }
    }

    // Analyze agent usage patterns
    this.analyzeAgentUsage(content, findings);

    return findings;
  }

  getAllContent(skillContent) {
    let content = skillContent.rawContent || '';
    for (const file of skillContent.files) {
      content += '\n' + file.content;
    }
    return content;
  }

  analyzeAgentUsage(content, findings) {
    // Count Task calls
    const taskMatches = content.match(/Task\s*\(/gi) || [];
    const taskCount = taskMatches.length;

    if (taskCount > 5) {
      findings.medium.push({
        title: '[Behavior Analysis] Large number of Task calls',
        description: `Detected ${taskCount} Task calls, review necessity of each`,
        scanner: 'SubAgentScanner'
      });
    }

    if (taskCount > 10) {
      findings.high.push({
        title: '[Behavior Analysis] Excessive Task calls',
        description: `Detected ${taskCount} Task calls, may affect performance or indicate abuse`,
        scanner: 'SubAgentScanner'
      });
    }

    // Check for unknown agent types
    const agentTypePattern = /subagent_type\s*[=:]\s*['"]?([a-zA-Z0-9-_]+)['"]?/gi;
    let match;
    const foundTypes = new Set();

    while ((match = agentTypePattern.exec(content)) !== null) {
      foundTypes.add(match[1].toLowerCase());
    }

    for (const type of foundTypes) {
      const isKnown = this.knownAgentTypes.some(kt =>
        kt.toLowerCase() === type
      );

      if (!isKnown) {
        findings.low.push({
          title: '[Agent Type] Non-standard type',
          description: `Using non-standard agent type: ${type}`,
          scanner: 'SubAgentScanner'
        });
      }
    }

    // Check parallel agents abuse
    const parallelPattern = /parallel|concurrent/gi;
    const hasParallel = parallelPattern.test(content);

    if (hasParallel && taskCount > 3) {
      findings.medium.push({
        title: '[Behavior Analysis] Parallel Agent execution',
        description: 'Skill uses parallel agent execution, ensure reasonable resource usage',
        scanner: 'SubAgentScanner'
      });
    }

    // Check for sensitive tool combinations
    const hasReadTools = /Read|Glob|Grep/gi.test(content);
    const hasWriteTools = /Write|Edit/gi.test(content);
    const hasNetworkTools = /WebFetch|curl|wget|http/gi.test(content);
    const hasBashTools = /Bash/gi.test(content);

    const dangerousCombos = [];
    if (hasReadTools && hasNetworkTools) dangerousCombos.push('Read+Network');
    if (hasBashTools && hasNetworkTools) dangerousCombos.push('Shell+Network');
    if (hasReadTools && hasWriteTools && hasBashTools) dangerousCombos.push('Full Access');

    if (dangerousCombos.length > 0) {
      findings.high.push({
        title: '[Behavior Analysis] Dangerous tool combination',
        description: `Sub-agents use dangerous tool combination: ${dangerousCombos.join(', ')}`,
        scanner: 'SubAgentScanner'
      });
    }
  }
}
