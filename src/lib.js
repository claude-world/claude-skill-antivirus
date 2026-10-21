/**
 * Programmatic API for claude-skill-antivirus.
 *
 * Importing the package (`claude-skill-antivirus`) resolves here, so it has no
 * CLI side effects. The `skill-install` / `skill-batch-scan` binaries remain the
 * command-line entry points.
 *
 * @example
 *   import { SecurityScanner, loadSkill } from 'claude-skill-antivirus';
 *   const scanner = new SecurityScanner();
 *   const skill = await loadSkill('./path/to/skill');
 *   const result = await scanner.scan(skill);
 *   console.log(result.riskLevel, result.score, result.findings);
 */
export { SecurityScanner } from './scanner/index.js';
export { SkillDownloader, SCAN_LIMITS } from './utils/downloader.js';
export { SkillInstaller } from './utils/installer.js';
export { VERSION } from './version.js';

import { SkillDownloader } from './utils/downloader.js';

/**
 * Load and parse a skill from a local path, GitHub URL, SkillsMP URL, or zip.
 * @param {string} source
 * @returns {Promise<object>} SkillContent with a populated `files` array.
 */
export function loadSkill(source) {
  return new SkillDownloader().fetch(source);
}
