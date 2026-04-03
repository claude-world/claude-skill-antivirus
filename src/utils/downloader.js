import fetch from 'node-fetch';
import { readFile, stat } from 'fs/promises';
import { parse as parseYaml } from 'yaml';
import path from 'path';
import AdmZip from 'adm-zip';

/**
 * SkillDownloader - Fetches and parses skill content from various sources
 */
export class SkillDownloader {
  constructor() {
    this.supportedSources = ['skillsmp.com', 'github.com', 'local'];
  }

  /**
   * Fetch skill from URL or local path
   * @param {string} source - URL or local file path
   * @returns {Promise<SkillContent>}
   */
  async fetch(source) {
    if (this.isLocalPath(source)) {
      return this.fetchLocal(source);
    }

    if (source.includes('skillsmp.com')) {
      return this.fetchFromSkillsMP(source);
    }

    if (source.includes('github.com')) {
      return this.fetchFromGitHub(source);
    }

    throw new Error(`Unsupported source: ${source}`);
  }

  isLocalPath(source) {
    return !source.startsWith('http://') && !source.startsWith('https://');
  }

  async fetchLocal(filePath) {
    const stats = await stat(filePath);

    if (stats.isDirectory()) {
      // Look for SKILL.md in directory
      const skillMdPath = path.join(filePath, 'SKILL.md');
      const content = await readFile(skillMdPath, 'utf-8');
      return this.parseSkillMd(content, filePath);
    }

    if (filePath.endsWith('.zip')) {
      return this.extractZip(filePath);
    }

    const content = await readFile(filePath, 'utf-8');
    return this.parseSkillMd(content, path.dirname(filePath));
  }

  async fetchFromSkillsMP(url) {
    // Convert web URL to API/raw URL
    // Example: https://skillsmp.com/skills/n8n-io-n8n-claude-skills-create-pr-skill-md
    // We need to fetch the raw SKILL.md content

    // Try to get the zip download URL
    const zipUrl = this.getSkillsMPZipUrl(url);

    try {
      const response = await fetch(zipUrl);
      if (!response.ok) {
        throw new Error(`Failed to fetch skill: ${response.status}`);
      }

      const buffer = await response.buffer();
      return this.extractZipBuffer(buffer, url);
    } catch (error) {
      // Fallback: try to scrape the page content
      return this.scrapeSkillsMPPage(url);
    }
  }

  getSkillsMPZipUrl(url) {
    // Extract skill identifier from URL and construct download URL
    const skillId = url.split('/skills/').pop();
    return `https://skillsmp.com/api/skills/${skillId}/download`;
  }

  async scrapeSkillsMPPage(url) {
    const response = await fetch(url);
    const html = await response.text();

    // Extract skill content from the page
    // Look for the SKILL.md content in the page
    const skillContent = this.extractSkillFromHtml(html);

    return {
      name: this.extractNameFromUrl(url),
      source: url,
      files: [{
        name: 'SKILL.md',
        content: skillContent,
        path: 'SKILL.md'
      }],
      metadata: this.parseSkillMetadata(skillContent),
      rawContent: skillContent
    };
  }

  extractSkillFromHtml(html) {
    // Extract content between common markers
    // This is a simplified extraction - real implementation would use proper HTML parsing

    // Try to find the skill content in various formats
    const patterns = [
      /```markdown\n([\s\S]*?)```/,
      /```md\n([\s\S]*?)```/,
      /<pre[^>]*class="[^"]*skill[^"]*"[^>]*>([\s\S]*?)<\/pre>/i,
      /<code[^>]*>([\s\S]*?)<\/code>/
    ];

    for (const pattern of patterns) {
      const match = html.match(pattern);
      if (match) {
        return this.decodeHtmlEntities(match[1]);
      }
    }

    // Fallback: construct skill from visible metadata
    return this.constructSkillFromPageData(html);
  }

  constructSkillFromPageData(html) {
    const nameMatch = html.match(/<h1[^>]*>([^<]+)<\/h1>/i) ||
                      html.match(/name['"]\s*:\s*['"]([^'"]+)['"]/);
    const descMatch = html.match(/description['"]\s*:\s*['"]([^'"]+)['"]/);
    const toolsMatch = html.match(/allowed-tools['"]\s*:\s*['"]([^'"]+)['"]/);

    const name = nameMatch ? nameMatch[1].trim() : 'unknown-skill';
    const description = descMatch ? descMatch[1] : '';
    const allowedTools = toolsMatch ? toolsMatch[1] : '';

    // Construct a basic SKILL.md
    return `---
name: ${name}
description: ${description}
allowed-tools: ${allowedTools}
---

# ${name}

${description}

(Extracted from page - full content may not be available)
`;
  }

  decodeHtmlEntities(text) {
    const entities = {
      '&lt;': '<',
      '&gt;': '>',
      '&amp;': '&',
      '&quot;': '"',
      '&#39;': "'",
      '&nbsp;': ' '
    };

    return text.replace(/&[^;]+;/g, entity => entities[entity] || entity);
  }

  extractNameFromUrl(url) {
    const parts = url.split('/');
    return parts[parts.length - 1] || 'unknown-skill';
  }

  async fetchFromGitHub(url) {
    // If URL points to a repo root (no file path), try SKILL.md on default branch
    const repoRootMatch = url.match(/^https?:\/\/github\.com\/([^/]+)\/([^/]+)\/?$/);
    if (repoRootMatch) {
      const [, owner, repo] = repoRootMatch;
      // Try common default branches
      for (const branch of ['main', 'master']) {
        const rawUrl = `https://raw.githubusercontent.com/${owner}/${repo}/${branch}/SKILL.md`;
        const response = await fetch(rawUrl);
        if (response.ok) {
          const content = await response.text();
          return this.parseSkillMd(content, url);
        }
      }
      throw new Error(`No SKILL.md found at ${url} (tried main and master branches)`);
    }

    // Convert GitHub URL to raw content URL
    const rawUrl = this.convertToGitHubRaw(url);

    const response = await fetch(rawUrl);
    if (!response.ok) {
      throw new Error(`Failed to fetch from GitHub: ${response.status}`);
    }

    const content = await response.text();
    return this.parseSkillMd(content, url);
  }

  convertToGitHubRaw(url) {
    // https://github.com/user/repo/blob/main/skills/SKILL.md
    // -> https://raw.githubusercontent.com/user/repo/main/skills/SKILL.md
    return url
      .replace('github.com', 'raw.githubusercontent.com')
      .replace('/blob/', '/');
  }

  async extractZip(filePath) {
    const zip = new AdmZip(filePath);
    return this.parseZipContents(zip, filePath);
  }

  async extractZipBuffer(buffer, source) {
    const zip = new AdmZip(buffer);
    return this.parseZipContents(zip, source);
  }

  parseZipContents(zip, source) {
    const entries = zip.getEntries();
    const files = [];
    let skillMdContent = null;

    for (const entry of entries) {
      if (!entry.isDirectory) {
        const content = entry.getData().toString('utf-8');
        files.push({
          name: entry.name,
          content: content,
          path: entry.entryName
        });

        if (entry.name === 'SKILL.md' || entry.entryName.endsWith('/SKILL.md')) {
          skillMdContent = content;
        }
      }
    }

    if (!skillMdContent && files.length > 0) {
      // Use first markdown file as skill content
      const mdFile = files.find(f => f.name.endsWith('.md'));
      if (mdFile) {
        skillMdContent = mdFile.content;
      }
    }

    const metadata = skillMdContent ? this.parseSkillMetadata(skillMdContent) : {};

    return {
      name: metadata.name || this.extractNameFromUrl(source),
      source: source,
      files: files,
      metadata: metadata,
      rawContent: skillMdContent || ''
    };
  }

  parseSkillMd(content, source) {
    const metadata = this.parseSkillMetadata(content);

    return {
      name: metadata.name || this.extractNameFromUrl(source),
      source: source,
      files: [{
        name: 'SKILL.md',
        content: content,
        path: 'SKILL.md'
      }],
      metadata: metadata,
      rawContent: content
    };
  }

  parseSkillMetadata(content) {
    const metadata = {};

    // Parse YAML frontmatter
    const frontmatterMatch = content.match(/^---\n([\s\S]*?)\n---/);
    if (frontmatterMatch) {
      try {
        const yamlContent = parseYaml(frontmatterMatch[1]);
        Object.assign(metadata, yamlContent);
      } catch (e) {
        // YAML parse failed, try line-by-line
        this.parseMetadataLines(frontmatterMatch[1], metadata);
      }
    }

    // Also look for table-style metadata (like SkillsMP format)
    const tablePatterns = [
      /\|\s*name\s*\|\s*([^|]+)\|/i,
      /\|\s*description\s*\|\s*([^|]+)\|/i,
      /\|\s*allowed-tools\s*\|\s*([^|]+)\|/i,
      /\|\s*author\s*\|\s*([^|]+)\|/i
    ];

    const tableMatch = content.match(/\|\s*name\s*\|/i);
    if (tableMatch) {
      tablePatterns.forEach(pattern => {
        const match = content.match(pattern);
        if (match) {
          const key = pattern.source.match(/\|\s*(\w+)/)[1];
          metadata[key] = match[1].trim();
        }
      });
    }

    // Extract allowed-tools specifically (critical for security)
    const toolsMatch = content.match(/allowed-tools['":\s]+([^\n|]+)/i);
    if (toolsMatch && !metadata['allowed-tools']) {
      metadata['allowed-tools'] = toolsMatch[1].trim();
    }

    return metadata;
  }

  parseMetadataLines(text, metadata) {
    const lines = text.split('\n');
    for (const line of lines) {
      const match = line.match(/^(\w[\w-]*)\s*:\s*(.+)$/);
      if (match) {
        metadata[match[1]] = match[2].trim();
      }
    }
  }
}
