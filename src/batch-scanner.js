#!/usr/bin/env node

/**
 * Batch Scanner - Scans all skills from SkillsMP API
 * Usage: node src/batch-scanner.js --api-key <key> [options]
 */

import { program } from 'commander';
import { writeFile, mkdir } from 'fs/promises';
import path from 'path';
import ora from 'ora';
import chalk from 'chalk';
import { SecurityScanner } from './scanner/index.js';
import { setLanguage } from './i18n/index.js';
import { VERSION } from './version.js';

const SKILLSMP_API_BASE = 'https://skillsmp.com/api/v1';

class BatchScanner {
  constructor(apiKey, options = {}) {
    this.apiKey = apiKey;
    this.limit = options.limit || 100;
    this.maxPages = options.maxPages || Infinity;
    this.outputDir = options.outputDir || './scan-reports';
    this.verbose = options.verbose || false;
    this.logProgress = options.logProgress || false;
    this.scanner = new SecurityScanner(this.verbose);
    this.results = {
      scannedAt: new Date().toISOString(),
      totalSkills: 0,
      scannedSkills: 0,
      byRiskLevel: {
        CRITICAL: [],
        HIGH: [],
        MEDIUM: [],
        LOW: [],
        SAFE: []
      },
      errors: [],
      summary: {}
    };
  }

  async fetchSkillsList(page = 1) {
    const url = `${SKILLSMP_API_BASE}/skills/search?q=*&page=${page}&limit=${this.limit}&sortBy=updatedAt`;

    const response = await fetch(url, {
      headers: {
        'Authorization': `Bearer ${this.apiKey}`,
        'Content-Type': 'application/json'
      }
    });

    if (!response.ok) {
      throw new Error(`API request failed: ${response.status} ${response.statusText}`);
    }

    return response.json();
  }

  async fetchSkillContent(skill) {
    // The SkillsMP API exposes a skill's manifest (rawContent) or metadata,
    // never its scripts, so every verdict here is manifest-only (#33).
    const content = skill.rawContent || this.constructSkillContent(skill);

    return {
      name: skill.name || skill.id,
      source: `skillsmp://${skill.id}`,
      files: [{
        name: 'SKILL.md',
        content: content,
        path: 'SKILL.md'
      }],
      metadata: {
        name: skill.name,
        description: skill.description,
        author: skill.author,
        'allowed-tools': skill.allowedTools || skill['allowed-tools']
      },
      rawContent: content,
      loaderFindings: [{
        risk: 'medium',
        title: 'Only the manifest was analyzed',
        description: 'The SkillsMP API provides only the skill manifest, so executable files in the skill were NOT analyzed. Scan the skill directory or repository for a complete verdict.',
        location: `skillsmp://${skill.id}`,
        scanner: 'SkillsMPBatch'
      }],
      coverage: { filesScanned: 1, bytesScanned: Buffer.byteLength(content), truncatedFiles: 0, complete: false }
    };
  }

  constructSkillContent(skill) {
    // Build a SKILL.md-like content from API response fields
    let content = '';

    if (skill.name) content += `# ${skill.name}\n\n`;
    if (skill.description) content += `${skill.description}\n\n`;
    if (skill.allowedTools || skill['allowed-tools']) {
      content += `allowed-tools: ${skill.allowedTools || skill['allowed-tools']}\n\n`;
    }
    if (skill.content) content += skill.content + '\n';
    if (skill.instructions) content += skill.instructions + '\n';
    if (skill.prompt) content += skill.prompt + '\n';

    return content || '(No content available)';
  }

  async scanAllSkills(spinner) {
    let page = 1;
    let hasMore = true;

    // First request to get total
    const firstResponse = await this.fetchSkillsList(1);
    this.results.totalSkills = firstResponse.data.pagination.total;
    const totalPages = Math.min(firstResponse.data.pagination.totalPages, this.maxPages);

    const progressMsg = `Found ${this.results.totalSkills} skills across ${totalPages} pages`;
    spinner.text = progressMsg;
    if (this.logProgress) console.log(`[PROGRESS] ${progressMsg}`);

    // Process first page
    await this.processSkillsPage(firstResponse.data.skills, spinner);
    page++;

    // Process remaining pages
    while (page <= totalPages) {
      const pageMsg = `Page ${page}/${totalPages} | Scanned: ${this.results.scannedSkills} | Critical: ${this.results.byRiskLevel.CRITICAL.length} | High: ${this.results.byRiskLevel.HIGH.length}`;
      spinner.text = pageMsg;

      // Log progress every 10 pages
      if (this.logProgress && page % 10 === 0) {
        console.log(`[PROGRESS] ${pageMsg}`);
      }

      try {
        const response = await this.fetchSkillsList(page);
        await this.processSkillsPage(response.data.skills, spinner);

        if (!response.data.pagination.hasNext) break;
        page++;

        // Rate limiting - small delay between pages
        await this.delay(200);
      } catch (error) {
        this.results.errors.push({
          type: 'page_fetch',
          page,
          error: error.message
        });
        page++;
      }
    }
  }

  async processSkillsPage(skills, spinner) {
    for (const skill of skills) {
      try {
        const skillContent = await this.fetchSkillContent(skill);
        const scanResult = await this.scanner.scan(skillContent);

        this.results.scannedSkills++;
        this.results.byRiskLevel[scanResult.riskLevel].push({
          id: skill.id,
          name: skill.name,
          author: skill.author,
          score: scanResult.score,
          riskLevel: scanResult.riskLevel,
          findingsCount: {
            critical: scanResult.findings.critical.length,
            high: scanResult.findings.high.length,
            medium: scanResult.findings.medium.length,
            low: scanResult.findings.low.length,
            info: scanResult.findings.info.length
          },
          topFindings: this.getTopFindings(scanResult.findings)
        });

        if (this.verbose && scanResult.riskLevel !== 'SAFE') {
          spinner.stop();
          console.log(chalk.yellow(`  ⚠️  ${skill.name}: ${scanResult.riskLevel}`));
          spinner.start();
        }
      } catch (error) {
        this.results.errors.push({
          type: 'skill_scan',
          skillId: skill.id,
          skillName: skill.name,
          error: error.message
        });
      }
    }
  }

  getTopFindings(findings) {
    const top = [];

    // Get top 3 critical/high findings
    for (const finding of findings.critical.slice(0, 2)) {
      top.push({ level: 'CRITICAL', title: finding.title });
    }
    for (const finding of findings.high.slice(0, 2)) {
      top.push({ level: 'HIGH', title: finding.title });
    }

    return top.slice(0, 3);
  }

  generateSummary() {
    this.results.summary = {
      totalScanned: this.results.scannedSkills,
      totalErrors: this.results.errors.length,
      riskDistribution: {
        critical: this.results.byRiskLevel.CRITICAL.length,
        high: this.results.byRiskLevel.HIGH.length,
        medium: this.results.byRiskLevel.MEDIUM.length,
        low: this.results.byRiskLevel.LOW.length,
        safe: this.results.byRiskLevel.SAFE.length
      },
      percentageSafe: ((this.results.byRiskLevel.SAFE.length / this.results.scannedSkills) * 100).toFixed(2) + '%',
      percentageRisky: (((this.results.scannedSkills - this.results.byRiskLevel.SAFE.length) / this.results.scannedSkills) * 100).toFixed(2) + '%'
    };
  }

  async saveReport() {
    await mkdir(this.outputDir, { recursive: true });

    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');

    // Save full JSON report
    const jsonPath = path.join(this.outputDir, `skillsmp-scan-${timestamp}.json`);
    await writeFile(jsonPath, JSON.stringify(this.results, null, 2));

    // Save summary markdown report
    const mdPath = path.join(this.outputDir, `skillsmp-scan-${timestamp}.md`);
    const markdown = this.generateMarkdownReport();
    await writeFile(mdPath, markdown);

    // Save critical/high findings separately
    const criticalPath = path.join(this.outputDir, `critical-findings-${timestamp}.json`);
    await writeFile(criticalPath, JSON.stringify({
      critical: this.results.byRiskLevel.CRITICAL,
      high: this.results.byRiskLevel.HIGH
    }, null, 2));

    return { jsonPath, mdPath, criticalPath };
  }

  generateMarkdownReport() {
    const s = this.results.summary;

    let md = `# SkillsMP Security Scan Report

**Scan Date**: ${this.results.scannedAt}
**Total Skills on Platform**: ${this.results.totalSkills}
**Skills Scanned**: ${s.totalScanned}
**Errors**: ${s.totalErrors}

> **Coverage**: the SkillsMP API exposes only each skill's manifest, so these
> verdicts cover \`SKILL.md\` alone; scripts and other files were not analyzed.
> Scan a skill's directory or repository with \`skill-install <source> --scan-only\`
> for a complete verdict.

## Risk Distribution

| Risk Level | Count | Percentage |
|------------|-------|------------|
| 🔴 CRITICAL | ${s.riskDistribution.critical} | ${((s.riskDistribution.critical / s.totalScanned) * 100).toFixed(2)}% |
| 🟠 HIGH | ${s.riskDistribution.high} | ${((s.riskDistribution.high / s.totalScanned) * 100).toFixed(2)}% |
| 🟡 MEDIUM | ${s.riskDistribution.medium} | ${((s.riskDistribution.medium / s.totalScanned) * 100).toFixed(2)}% |
| 🟢 LOW | ${s.riskDistribution.low} | ${((s.riskDistribution.low / s.totalScanned) * 100).toFixed(2)}% |
| ✅ SAFE | ${s.riskDistribution.safe} | ${s.percentageSafe} |

## Summary

- **Safe Skills**: ${s.percentageSafe}
- **Risky Skills**: ${s.percentageRisky}

## Critical Findings (Top 20)

`;

    // List top 20 critical skills
    const criticalSkills = this.results.byRiskLevel.CRITICAL.slice(0, 20);
    for (const skill of criticalSkills) {
      md += `### ${skill.name}\n`;
      md += `- **Author**: ${skill.author || 'Unknown'}\n`;
      md += `- **Score**: ${skill.score}/100\n`;
      md += `- **Findings**: Critical: ${skill.findingsCount.critical}, High: ${skill.findingsCount.high}\n`;
      if (skill.topFindings.length > 0) {
        md += `- **Issues**:\n`;
        for (const f of skill.topFindings) {
          md += `  - [${f.level}] ${f.title}\n`;
        }
      }
      md += '\n';
    }

    md += `\n## High Risk Skills (Top 20)\n\n`;

    const highSkills = this.results.byRiskLevel.HIGH.slice(0, 20);
    for (const skill of highSkills) {
      md += `- **${skill.name}** (Score: ${skill.score}) - ${skill.findingsCount.high} high, ${skill.findingsCount.medium} medium findings\n`;
    }

    return md;
  }

  delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

// CLI Setup
program
  .name('batch-scanner')
  .description('Scan all skills from SkillsMP for security issues')
  .version(VERSION)
  .requiredOption('-k, --api-key <key>', 'SkillsMP API key')
  .option('-l, --limit <number>', 'Skills per page', '100')
  .option('-p, --max-pages <number>', 'Maximum pages to scan (default: all)')
  .option('-o, --output <dir>', 'Output directory for reports', './scan-reports')
  .option('-v, --verbose', 'Show verbose output')
  .option('--log-progress', 'Log progress to stdout (useful for background runs)')
  .option('--lang <lang>', 'Language (en, zh-TW)', 'en');

program.parse();

const options = program.opts();

// Set language
setLanguage(options.lang);

// Main execution
async function main() {
  console.log(chalk.cyan('🔧 Claude Skill Antivirus - Batch Scanner v' + VERSION));
  console.log(chalk.gray('─'.repeat(50)));

  const batchScanner = new BatchScanner(options.apiKey, {
    limit: parseInt(options.limit),
    maxPages: options.maxPages ? parseInt(options.maxPages) : Infinity,
    outputDir: options.output,
    verbose: options.verbose,
    logProgress: options.logProgress
  });

  const spinner = ora('Connecting to SkillsMP API...').start();

  try {
    await batchScanner.scanAllSkills(spinner);
    batchScanner.generateSummary();

    spinner.succeed(`Scanned ${batchScanner.results.scannedSkills} skills`);

    // Print summary
    console.log('\n' + chalk.cyan('📊 Scan Summary'));
    console.log(chalk.gray('─'.repeat(50)));

    const s = batchScanner.results.summary;
    console.log(`  🔴 Critical: ${chalk.red(s.riskDistribution.critical)}`);
    console.log(`  🟠 High:     ${chalk.yellow(s.riskDistribution.high)}`);
    console.log(`  🟡 Medium:   ${chalk.yellow(s.riskDistribution.medium)}`);
    console.log(`  🟢 Low:      ${chalk.green(s.riskDistribution.low)}`);
    console.log(`  ✅ Safe:     ${chalk.green(s.riskDistribution.safe)}`);
    console.log();
    console.log(`  Safe: ${chalk.green(s.percentageSafe)} | Risky: ${chalk.red(s.percentageRisky)}`);

    // Save reports
    spinner.start('Saving reports...');
    const paths = await batchScanner.saveReport();
    spinner.succeed('Reports saved');

    console.log('\n' + chalk.cyan('📁 Report Files'));
    console.log(`  Full report: ${paths.jsonPath}`);
    console.log(`  Summary:     ${paths.mdPath}`);
    console.log(`  Critical:    ${paths.criticalPath}`);

    // Exit with appropriate code
    if (s.riskDistribution.critical > 0) {
      console.log('\n' + chalk.red('⚠️  Critical security issues found in some skills!'));
      process.exit(1);
    }

  } catch (error) {
    spinner.fail('Scan failed');
    console.error(chalk.red('Error:'), error.message);
    process.exit(1);
  }
}

main();
