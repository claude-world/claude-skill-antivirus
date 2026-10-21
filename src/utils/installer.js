import { mkdir, writeFile } from 'fs/promises';
import path from 'path';
import os from 'os';

// Version-control metadata is never part of an installed skill.
const VCS_DIRS = new Set(['.git', '.svn', '.hg']);

/**
 * SkillInstaller - Handles the actual installation of skills
 *
 * Installation paths:
 * - User level (--global): ~/.claude/skills/
 * - Project level (default): ./.claude/skills/
 */
export class SkillInstaller {
  constructor(options = {}) {
    this.global = options.global || false;
    this.outputDir = this.getOutputDir();
  }

  getOutputDir() {
    if (this.global) {
      // User level: ~/.claude/skills/
      return path.join(os.homedir(), '.claude', 'skills');
    } else {
      // Project level: ./.claude/skills/
      return path.join(process.cwd(), '.claude', 'skills');
    }
  }

  /**
   * Install a skill to the output directory
   * @param {SkillContent} skillContent - Parsed skill content
   * @returns {Promise<string>} - Installation path
   */
  async install(skillContent) {
    // Never install what could not be fully scanned: truncated or unread files
    // would be installed incomplete, and their unscanned bytes are unvetted.
    if (skillContent.coverage && skillContent.coverage.complete === false) {
      throw new Error('Refusing to install: the skill was not fully scanned (see the findings above). Review it manually or install from a complete source.');
    }

    const skillDir = path.resolve(this.outputDir, this.sanitizeName(skillContent.name));

    // Validate every destination before writing anything (fail closed): an
    // archive entry like "../../.bashrc" must never escape the skill directory.
    const writes = [];
    for (const file of skillContent.files) {
      const rel = file.path.replace(/\\/g, '/');
      if (rel.split('/').some((seg) => VCS_DIRS.has(seg))) continue;
      if (file.truncated) {
        throw new Error(`Refusing to install: ${file.path} was only partially scanned.`);
      }
      const dest = path.resolve(skillDir, rel);
      if (!dest.startsWith(skillDir + path.sep)) {
        throw new Error(`Refusing to install: "${file.path}" would be written outside the skill directory.`);
      }
      writes.push({ dest, file });
    }

    await mkdir(skillDir, { recursive: true });

    for (const { dest, file } of writes) {
      await mkdir(path.dirname(dest), { recursive: true });
      // Exact bytes when available, so binaries are not mangled by re-encoding.
      await writeFile(dest, file.data ?? file.content);
    }

    // Write metadata file
    const metadataPath = path.join(skillDir, '.skill-meta.json');
    await writeFile(metadataPath, JSON.stringify({
      name: skillContent.name,
      source: skillContent.source,
      installedAt: new Date().toISOString(),
      metadata: skillContent.metadata
    }, null, 2), 'utf-8');

    return skillDir;
  }

  sanitizeName(name) {
    const sanitized = String(name ?? '')
      .toLowerCase()
      .replace(/[^a-z0-9-_]/g, '-')
      .replace(/-+/g, '-')
      .replace(/^-|-$/g, '');
    // An empty name would install straight into the shared skills directory.
    return sanitized || 'unnamed-skill';
  }
}
