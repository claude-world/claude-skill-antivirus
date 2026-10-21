import { DangerousCommandScanner } from './dangerous-commands.js';
import { PermissionScanner } from './permissions.js';
import { ExternalConnectionScanner } from './external-connections.js';
import { PatternScanner } from './patterns.js';
import { DataExfiltrationScanner } from './data-exfiltration.js';
import { MCPSecurityScanner } from './mcp-security.js';
import { SSRFScanner } from './ssrf-scanner.js';
import { DependencyScanner } from './dependency-scanner.js';
import { SubAgentScanner } from './subagent-scanner.js';
import { FileArtifactScanner } from './file-artifacts.js';
import { t } from '../i18n/index.js';

/**
 * SecurityScanner - Main scanner that orchestrates all security checks
 * Integrated antivirus scanning engine for detecting malicious behavior in Skills
 *
 * 10 Scanning Engines:
 * 1. DangerousCommandScanner - Dangerous command detection
 * 2. PermissionScanner - Permission scope analysis
 * 3. ExternalConnectionScanner - External connection analysis
 * 4. PatternScanner - Malicious pattern matching
 * 5. DataExfiltrationScanner - Data exfiltration detection
 * 6. MCPSecurityScanner - MCP Server security checks
 * 7. SSRFScanner - SSRF/Cloud attack detection
 * 8. DependencyScanner - Dependency security analysis
 * 9. SubAgentScanner - Sub-agent attack detection
 * 10. FileArtifactScanner - Compiled/binary/archive artifact detection
 */
export class SecurityScanner {
  constructor(verbose = false) {
    this.verbose = verbose;
    this.scanners = [
      new DangerousCommandScanner(),      // Dangerous command detection
      new PermissionScanner(),             // Permission scope analysis
      new ExternalConnectionScanner(),     // External connection analysis
      new PatternScanner(),                // Malicious pattern matching
      new DataExfiltrationScanner(),       // Data exfiltration detection
      new MCPSecurityScanner(),            // MCP Server security checks
      new SSRFScanner(),                   // SSRF/Cloud attack detection
      new DependencyScanner(),             // Dependency security analysis
      new SubAgentScanner(),               // Sub-agent attack detection
      new FileArtifactScanner()            // Compiled/binary/archive artifact detection
    ];
  }

  /**
   * Run all security scans on the skill content
   * @param {SkillContent} skillContent
   * @returns {Promise<ScanResult>}
   */
  async scan(skillContent) {
    const findings = {
      critical: [],
      high: [],
      medium: [],
      low: [],
      info: []
    };

    // Run all scanners
    for (const scanner of this.scanners) {
      const scannerFindings = await scanner.scan(skillContent);
      this.mergeFindings(findings, scannerFindings);
    }

    // Merge structural findings the loader produced while reading the skill
    // (skipped/anomalous dirs, symlinks, truncation, scan-limit hits). These
    // ensure an unusual input can never silently pass as SAFE.
    if (Array.isArray(skillContent.loaderFindings)) {
      for (const f of skillContent.loaderFindings) {
        const level = findings[f.risk] ? f.risk : 'low';
        findings[level].push({
          title: f.title,
          description: f.description,
          location: f.location,
          scanner: f.scanner || 'Loader',
        });
      }
    }

    // Calculate risk level and score
    const riskLevel = this.calculateRiskLevel(findings);
    const score = this.calculateScore(findings);

    return {
      skillName: skillContent.name,
      source: skillContent.source,
      scannedAt: new Date().toISOString(),
      riskLevel,
      score,
      findings,
      summary: this.generateSummary(findings, riskLevel)
    };
  }

  mergeFindings(target, source) {
    for (const level of Object.keys(target)) {
      if (source[level]) {
        target[level].push(...source[level]);
      }
    }
  }

  calculateRiskLevel(findings) {
    if (findings.critical.length > 0) return 'CRITICAL';
    if (findings.high.length > 0) return 'HIGH';
    if (findings.medium.length > 0) return 'MEDIUM';
    if (findings.low.length > 0) return 'LOW';
    return 'SAFE';
  }

  calculateScore(findings) {
    // Start with 100, deduct based on findings
    let score = 100;

    score -= findings.critical.length * 30;
    score -= findings.high.length * 20;
    score -= findings.medium.length * 10;
    score -= findings.low.length * 5;
    // Info doesn't affect score

    return Math.max(0, Math.min(100, score));
  }

  generateSummary(findings, riskLevel) {
    const total = Object.values(findings).reduce((sum, arr) => sum + arr.length, 0);

    return {
      totalFindings: total,
      riskLevel,
      recommendation: this.getRecommendation(riskLevel)
    };
  }

  getRecommendation(riskLevel) {
    return t(`recommendations.${riskLevel.toLowerCase()}`);
  }
}
