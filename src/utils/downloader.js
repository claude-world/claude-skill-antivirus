import { constants as fsConstants } from 'fs';
import { open, readFile, readdir, readlink, realpath, lstat, stat } from 'fs/promises';
import { parse as parseYaml } from 'yaml';
import path from 'path';
import AdmZip from 'adm-zip';

// --- Scan limits -------------------------------------------------------------
// A scanner must never silently give up. Every limit below, when hit, produces a
// finding and marks the scan incomplete, so a payload cannot evade analysis by
// hiding past a cap (and an incomplete scan is never installed).
export const SCAN_LIMITS = Object.freeze({
  maxFileBytes: 2 * 1024 * 1024, // bytes scanned per file
  maxTotalBytes: 16 * 1024 * 1024, // bytes scanned per skill
  maxFiles: 2000, // files scanned per skill
  maxEntries: 20000, // directory/archive entries enumerated per skill
  maxArchiveBytes: 64 * 1024 * 1024, // zip archives / downloads held in memory
  maxSymlinkLookups: 20, // GitHub API calls spent resolving symlink targets
});

// Directories a hand-authored skill should not normally ship. Their presence is
// flagged, but their contents are STILL scanned: skipping them silently is how a
// payload in `node_modules/x.js` or `__pycache__/*.pyc` would evade the scan.
const UNUSUAL_DIRS = new Set([
  '.git', '.svn', '.hg', 'node_modules', 'venv', '.venv',
  '__pycache__', 'site-packages', '.tox', '.mypy_cache', '.pytest_cache',
]);

const USER_AGENT = 'claude-skill-antivirus';
const NETWORK_TIMEOUT_MS = 30000;

// Open without following a symlink swapped in after lstat (TOCTOU) and without
// blocking on a FIFO. Both flags are POSIX-only; on Windows they are 0.
const OPEN_FLAGS = fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0) | (fsConstants.O_NONBLOCK ?? 0);

const toPosix = (p) => p.split(path.sep).join('/');

function escapesRoot(rel) {
  return rel === '..' || rel.startsWith('../') || path.posix.isAbsolute(rel);
}

function isOutsideRoot(root, target) {
  const rel = path.relative(root, target);
  return rel !== '' && (rel === '..' || rel.startsWith('..' + path.sep) || path.isAbsolute(rel));
}

// Heuristic binary sniff: a NUL byte, or many control bytes, means "not text".
function looksBinary(buf) {
  const n = Math.min(buf.length, 8192);
  let suspicious = 0;
  for (let i = 0; i < n; i++) {
    const b = buf[i];
    if (b === 0) return true;
    // control chars except tab(9) lf(10) vt(11) ff(12) cr(13) and ESC(27)
    if (b < 7 || (b > 13 && b < 32 && b !== 27)) suspicious++;
  }
  return n > 0 && suspicious / n > 0.3;
}

const hasUtf16Bom = (buf) => buf.length >= 2 &&
  ((buf[0] === 0xff && buf[1] === 0xfe) || (buf[0] === 0xfe && buf[1] === 0xff));

/**
 * Identify a file by its leading bytes, independent of its (attacker-chosen)
 * extension. `kind` is one of: executable, bytecode, archive, media, or null.
 */
export function sniffMagic(buf) {
  const at = (i, ...bytes) => bytes.every((b, k) => buf[i + k] === b);
  const ascii = (i, s) => buf.length >= i + s.length && buf.toString('latin1', i, i + s.length) === s;

  if (at(0, 0x7f, 0x45, 0x4c, 0x46)) return { kind: 'executable', type: 'ELF' };
  if (at(0, 0xfe, 0xed, 0xfa, 0xce) || at(0, 0xfe, 0xed, 0xfa, 0xcf) ||
      at(0, 0xce, 0xfa, 0xed, 0xfe) || at(0, 0xcf, 0xfa, 0xed, 0xfe)) return { kind: 'executable', type: 'Mach-O' };
  if (at(0, 0xca, 0xfe, 0xba, 0xbe)) return { kind: 'executable', type: 'Mach-O/Java class' };
  if (at(0, 0x00, 0x61, 0x73, 0x6d)) return { kind: 'executable', type: 'WebAssembly' };
  if (ascii(0, 'MZ') && looksBinary(buf)) return { kind: 'executable', type: 'PE (Windows)' };

  // Python bytecode: 2-byte version magic followed by \r\n (PEP 3147 / 552).
  if (buf.length >= 16 && buf[2] === 0x0d && buf[3] === 0x0a) {
    const version = buf.readUInt16LE(0);
    if (version >= 3000 && version < 4000) {
      const flags = buf.readUInt32LE(4);
      // PEP 552: bit 0 = hash-based, bit 1 = check_source. Hash-based without
      // check_source means Python loads it WITHOUT comparing to the .py source.
      const unchecked = version >= 3390 && (flags & 0b01) === 0b01 && (flags & 0b10) === 0;
      return { kind: 'bytecode', type: 'Python .pyc', pycUnchecked: unchecked };
    }
  }

  if (at(0, 0x50, 0x4b, 0x03, 0x04) || at(0, 0x50, 0x4b, 0x05, 0x06)) return { kind: 'archive', type: 'ZIP' };
  if (at(0, 0x1f, 0x8b)) return { kind: 'archive', type: 'gzip' };
  if (at(0, 0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c)) return { kind: 'archive', type: '7z' };
  if (ascii(0, 'Rar!')) return { kind: 'archive', type: 'RAR' };
  if (at(0, 0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00)) return { kind: 'archive', type: 'xz' };
  if (ascii(257, 'ustar')) return { kind: 'archive', type: 'tar' };

  if (at(0, 0x89, 0x50, 0x4e, 0x47)) return { kind: 'media', type: 'PNG' };
  if (at(0, 0xff, 0xd8, 0xff)) return { kind: 'media', type: 'JPEG' };
  if (ascii(0, 'GIF8')) return { kind: 'media', type: 'GIF' };
  if (ascii(0, 'RIFF') && (ascii(8, 'WEBP') || ascii(8, 'WAVE'))) return { kind: 'media', type: 'RIFF' };
  if (ascii(0, '%PDF')) return { kind: 'media', type: 'PDF' };
  if (ascii(0, 'wOFF') || ascii(0, 'wOF2') || ascii(0, 'OTTO') || at(0, 0x00, 0x01, 0x00, 0x00)) return { kind: 'media', type: 'font' };
  if (ascii(0, 'ID3') || ascii(0, 'OggS') || ascii(4, 'ftyp')) return { kind: 'media', type: 'audio/video' };
  if (at(0, 0x00, 0x00, 0x01, 0x00)) return { kind: 'media', type: 'ICO' };

  return { kind: null, type: null };
}

// Git's own object storage is compressed by design; recognize it by format so a
// checked-out repo is not reported as dozens of "binary files". Anything in
// .git/objects that does NOT match git's formats is treated like any other file.
function isVcsObject(relPath, buf) {
  const segs = relPath.split('/');
  const g = segs.indexOf('.git');
  if (g < 0) return false;
  const inner = segs.slice(g + 1);
  if (inner.length === 1 && inner[0] === 'index') return buf.toString('latin1', 0, 4) === 'DIRC';
  if (inner[0] !== 'objects') return false;
  const sig = buf.toString('latin1', 0, 4);
  if (['PACK', 'RIDX', 'MTME', 'CGPH', 'MIDX'].includes(sig) || (buf[0] === 0xff && sig.slice(1) === 'tOc')) return true;
  // loose object: zlib stream (CMF 0x78, header checksum divisible by 31)
  return buf.length >= 2 && buf[0] === 0x78 && ((buf[0] << 8) | buf[1]) % 31 === 0;
}

// Pull printable strings out of a binary (like `strings`), including UTF-16LE
// wide strings, so text engines can still see embedded commands/paths.
function extractStrings(buf, min = 4) {
  const out = [];
  let start = -1;
  for (let i = 0; i <= buf.length; i++) {
    const b = buf[i];
    const printable = i < buf.length && ((b >= 0x20 && b < 0x7f) || b === 0x09);
    if (printable && start < 0) start = i;
    if (!printable && start >= 0) {
      if (i - start >= min) out.push(buf.toString('latin1', start, i));
      start = -1;
    }
  }
  for (const offset of [0, 1]) {
    let run = [];
    // i runs one step past the end so the final run is always flushed
    for (let i = offset; i <= buf.length; i += 2) {
      const ok = i + 1 < buf.length && buf[i + 1] === 0 && buf[i] >= 0x20 && buf[i] < 0x7f;
      if (ok) {
        run.push(buf[i]);
        continue;
      }
      if (run.length >= min) out.push(Buffer.from(run).toString('latin1'));
      run = [];
    }
  }
  return out.join('\n');
}

function decodeForScan(buf, binary) {
  if (hasUtf16Bom(buf)) {
    if (buf[0] === 0xff) return buf.subarray(2).toString('utf16le');
    const swapped = Buffer.from(buf.subarray(2));
    swapped.swap16();
    return swapped.toString('utf16le');
  }
  if (binary) return extractStrings(buf);
  const text = buf.toString('utf-8');
  return text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
}

// Read at most `maxBytes` from the start of a file, never the whole file (a
// multi-GB file must not exhaust memory). The size comes from fstat on the open
// handle, so it describes exactly the file that was read.
async function readHead(filePath, maxBytes) {
  const fh = await open(filePath, OPEN_FLAGS);
  try {
    const st = await fh.stat();
    if (!st.isFile()) throw new Error('not a regular file');
    const buf = Buffer.alloc(Math.min(st.size, maxBytes));
    let off = 0;
    while (off < buf.length) {
      const { bytesRead } = await fh.read(buf, off, buf.length - off, off);
      if (bytesRead === 0) break;
      off += bytesRead;
    }
    return { data: buf.subarray(0, off), size: st.size };
  } finally {
    await fh.close();
  }
}

// Read at most `maxBytes` of a response body. With `strict`, a larger body is an
// error instead of being truncated (used for archives, which must be complete).
async function fetchBytes(url, maxBytes, { strict = false, headers = {} } = {}) {
  const res = await fetch(url, {
    headers: { 'User-Agent': USER_AGENT, ...headers },
    signal: AbortSignal.timeout(NETWORK_TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  if (!res.body) return Buffer.alloc(0);
  const reader = res.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (total <= maxBytes) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(Buffer.from(value.buffer, value.byteOffset, value.byteLength));
      total += value.byteLength;
    }
  } finally {
    await reader.cancel().catch(() => {});
  }
  if (strict && total > maxBytes) throw new Error(`response exceeds the ${maxBytes}-byte limit`);
  return Buffer.concat(chunks).subarray(0, maxBytes);
}

const encodePath = (p) => p.split('/').map(encodeURIComponent).join('/');

/**
 * SkillDownloader - Fetches and parses skill content from various sources.
 *
 * Every source produces the same `SkillContent` shape:
 *   { name, source, metadata, rawContent,
 *     files: [{ name, path, content, bytes, truncated, binary, magic, data? }],
 *     loaderFindings: [{ risk, title, description, location, scanner }],
 *     coverage: { filesScanned, bytesScanned, truncatedFiles, complete } }
 * so all engines see every file, and anything the loader could not fully read
 * surfaces as a finding instead of silently disappearing.
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

    let host;
    try {
      host = new URL(source).hostname.toLowerCase();
    } catch {
      throw new Error(`Invalid URL: ${source}`);
    }

    if (host === 'skillsmp.com' || host.endsWith('.skillsmp.com')) {
      return this.fetchFromSkillsMP(source);
    }

    if (host === 'github.com' || host === 'www.github.com') {
      return this.fetchFromGitHub(source);
    }

    throw new Error(`Unsupported source: ${source}`);
  }

  isLocalPath(source) {
    return !/^https?:\/\//i.test(source);
  }

  newContext(scanner) {
    const ctx = {
      findings: [],
      incomplete: false,
      add(risk, title, description, location) {
        ctx.findings.push({ risk, title, description, location, scanner });
      },
    };
    return ctx;
  }

  /**
   * Read candidate files under the scan limits. The manifest is read first,
   * then the smallest files, so padding junk cannot exhaust the budget before
   * the code that matters; anything left unread is reported, never dropped.
   */
  async collect(candidates, ctx) {
    const L = SCAN_LIMITS;
    const rank = (c) => (c.name === 'SKILL.md' ? c.path.split('/').length : Number.MAX_SAFE_INTEGER);
    const order = [...candidates].sort((a, b) =>
      rank(a) - rank(b) || (a.size ?? 0) - (b.size ?? 0) || (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));

    const files = [];
    const skipped = [];
    let totalBytes = 0;

    for (const c of order) {
      const budget = Math.min(L.maxFileBytes, L.maxTotalBytes - totalBytes);
      if (files.length >= L.maxFiles || budget <= 0) {
        skipped.push(c.path);
        continue;
      }

      let buf;
      let reportedSize;
      try {
        ({ data: buf, size: reportedSize } = await c.read(budget));
      } catch (error) {
        ctx.add('medium', 'File could not be read',
          `${c.path} could not be read (${error.message}) and was NOT scanned.`, c.path);
        ctx.incomplete = true;
        continue;
      }

      const size = Math.max(reportedSize ?? c.size ?? 0, buf.length);
      const truncated = size > buf.length;
      totalBytes += buf.length;

      const binary = !hasUtf16Bom(buf) && looksBinary(buf);
      const magic = sniffMagic(buf);
      const file = {
        name: c.name,
        path: c.path,
        content: decodeForScan(buf, binary),
        bytes: size,
        truncated,
        binary,
        magic: magic.kind,
        magicType: magic.type,
        pycUnchecked: Boolean(magic.pycUnchecked),
        vcsObject: isVcsObject(c.path, buf),
      };
      if (!truncated) file.data = buf; // exact bytes, for a faithful install

      if (truncated) {
        ctx.add('medium', 'File truncated before scanning',
          `${c.path} is ${size} bytes; only the first ${buf.length} bytes were scanned. A payload could hide past the limit.`, c.path);
        ctx.incomplete = true;
      }
      files.push(file);
    }

    if (skipped.length > 0) {
      ctx.add('high', 'Scan limit reached: files not scanned',
        `${skipped.length} file(s) were NOT scanned because the skill exceeds the scan limits (${L.maxFiles} files / ${L.maxTotalBytes} bytes), e.g. ${skipped.slice(0, 3).join(', ')}.`,
        skipped[0]);
      ctx.incomplete = true;
    }

    return { files, totalBytes };
  }

  finish({ files, totalBytes }, ctx, source, fallbackName) {
    const manifest = files
      .filter((f) => f.name === 'SKILL.md')
      .sort((a, b) => a.path.split('/').length - b.path.split('/').length)[0];
    let skillMdContent = manifest ? manifest.content : null;
    if (!skillMdContent) {
      const md = files.filter((f) => f.name.endsWith('.md')).sort((a, b) => (a.path < b.path ? -1 : 1))[0];
      if (md) skillMdContent = md.content;
      ctx.add('low', 'No SKILL.md manifest', 'No SKILL.md manifest was found; this may not be a valid skill.', '.');
    }
    if (files.length === 0) {
      ctx.add('medium', 'Empty skill', 'No readable files were found.', '.');
    }

    const metadata = skillMdContent ? this.parseSkillMetadata(skillMdContent) : {};
    return {
      name: metadata.name || fallbackName,
      source,
      files,
      metadata,
      rawContent: skillMdContent || '',
      loaderFindings: ctx.findings,
      coverage: {
        filesScanned: files.length,
        bytesScanned: totalBytes,
        truncatedFiles: files.filter((f) => f.truncated).length,
        complete: !ctx.incomplete,
      },
    };
  }

  async fetchLocal(filePath) {
    const stats = await stat(filePath);

    if (stats.isDirectory()) {
      // Walk the WHOLE directory, not just SKILL.md (#33).
      return this.parseLocalDirectory(filePath);
    }

    if (filePath.toLowerCase().endsWith('.zip')) {
      return this.extractZip(filePath);
    }

    // A bare SKILL.md path must still scan its siblings, otherwise pointing the
    // scanner straight at the manifest reintroduces the "only SKILL.md" bypass.
    if (path.basename(filePath) === 'SKILL.md') {
      return this.parseLocalDirectory(path.dirname(filePath));
    }

    // An explicitly chosen single file: scan exactly that file (installed as SKILL.md).
    const ctx = this.newContext('FileLoader');
    ctx.add('low', 'Only a single file was scanned',
      `Scanned ${path.basename(filePath)} alone; any sibling files of the skill were not analyzed. Point the scanner at the skill directory for full coverage.`,
      path.basename(filePath));
    const collected = await this.collect([{
      name: 'SKILL.md',
      path: 'SKILL.md',
      size: stats.size,
      read: (max) => readHead(filePath, max),
    }], ctx);
    return this.finish(collected, ctx, filePath, this.extractNameFromUrl(path.dirname(filePath)));
  }

  async parseLocalDirectory(dirPath) {
    const ctx = this.newContext('DirectoryLoader');
    const rootReal = await realpath(dirPath).catch(() => path.resolve(dirPath));
    const candidates = [];
    const seenDirs = new Set();
    let entries = 0;
    let enumerationCapped = false;
    const relOf = (full) => toPosix(path.relative(dirPath, full)) || path.basename(full);

    const handleSymlink = async (full) => {
      // NEVER follow a symlink: that is how a skill would read host files (a
      // link to /etc/passwd) or escape its own directory. Classify it instead.
      let target = '(unreadable)';
      try { target = await readlink(full); } catch { /* keep default */ }
      let resolved = null;
      try { resolved = await realpath(full); } catch { /* dangling link */ }
      if (!resolved || isOutsideRoot(rootReal, resolved)) {
        ctx.add('high', 'Symlink escapes the skill directory',
          `${relOf(full)} -> ${target} does not resolve inside the skill root and was NOT followed. Symlinks like this can read host files or escape the skill sandbox.`,
          relOf(full));
      } else {
        ctx.add('low', 'Symlink inside skill (not followed)',
          `${relOf(full)} -> ${target} is a symbolic link; its target is scanned in place, the link itself was not followed.`,
          relOf(full));
      }
    };

    const walk = async (dir) => {
      let real;
      try { real = await realpath(dir); } catch { real = dir; }
      if (seenDirs.has(real)) {
        ctx.add('medium', 'Directory loop detected',
          `A directory cycle was found at ${relOf(dir)} and skipped to avoid an infinite walk.`, relOf(dir));
        return;
      }
      seenDirs.add(real);

      let dirents;
      try {
        dirents = await readdir(dir, { withFileTypes: true });
      } catch (error) {
        ctx.add('medium', 'Unreadable directory',
          `Could not read ${relOf(dir)} (${error.code || error.message}); its contents were NOT scanned.`, relOf(dir));
        ctx.incomplete = true;
        return;
      }
      dirents.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));

      for (const entry of dirents) {
        if (++entries > SCAN_LIMITS.maxEntries) {
          if (!enumerationCapped) {
            ctx.add('high', 'Scan limit reached: too many entries',
              `The skill has more than ${SCAN_LIMITS.maxEntries} files and directories; the rest were NOT enumerated or scanned.`, relOf(dir));
            ctx.incomplete = true;
          }
          enumerationCapped = true;
          return;
        }

        const full = path.join(dir, entry.name);
        if (entry.isSymbolicLink()) {
          await handleSymlink(full);
        } else if (entry.isDirectory()) {
          if (UNUSUAL_DIRS.has(entry.name)) {
            ctx.add('low', `Unexpected directory in skill: ${entry.name}`,
              `A skill should not normally ship a ${entry.name}/ directory; its contents are still scanned but flagged as anomalous.`, relOf(full));
          }
          await walk(full);
        } else if (entry.isFile()) {
          // lstat size only orders the reads; readHead reports the real size.
          let size;
          try { size = (await lstat(full)).size; } catch { /* read will report */ }
          candidates.push({ name: entry.name, path: relOf(full), size, read: (max) => readHead(full, max) });
        } else {
          ctx.add('medium', 'Non-regular file in skill',
            `${relOf(full)} is not a regular file (socket, FIFO or device) and was skipped.`, relOf(full));
        }
      }
    };

    await walk(dirPath);
    const collected = await this.collect(candidates, ctx);
    return this.finish(collected, ctx, dirPath, this.extractNameFromUrl(path.resolve(dirPath)));
  }

  async fetchFromSkillsMP(url) {
    // Prefer the full skill archive; fall back to scraping the page (manifest only).
    try {
      const buffer = await fetchBytes(this.getSkillsMPZipUrl(url), SCAN_LIMITS.maxArchiveBytes, { strict: true });
      return await this.parseZipContents(new AdmZip(buffer), url);
    } catch (error) {
      return this.scrapeSkillsMPPage(url);
    }
  }

  getSkillsMPZipUrl(url) {
    const skillId = new URL(url).pathname.split('/skills/').pop().replace(/\/+$/, '');
    return `https://skillsmp.com/api/skills/${encodeURIComponent(skillId)}/download`;
  }

  async scrapeSkillsMPPage(url) {
    const html = (await fetchBytes(url, SCAN_LIMITS.maxFileBytes)).toString('utf-8');
    const skillContent = this.extractSkillFromHtml(html);

    const result = this.parseSkillMd(skillContent, url);
    result.loaderFindings.push({
      risk: 'medium',
      title: 'Only the manifest was analyzed',
      description: 'The skill archive could not be downloaded, so only the SKILL.md scraped from the page was scanned. Executable files in the skill were NOT analyzed.',
      location: url,
      scanner: 'SkillsMPLoader',
    });
    result.coverage.complete = false;
    return result;
  }

  extractSkillFromHtml(html) {
    const patterns = [
      /```markdown\n([\s\S]*?)```/,
      /```md\n([\s\S]*?)```/,
      /<pre[^>]*class="[^"]*skill[^"]*"[^>]*>([\s\S]*?)<\/pre>/i,
      /<code[^>]*>([\s\S]*?)<\/code>/,
    ];

    for (const pattern of patterns) {
      const match = html.match(pattern);
      if (match) {
        return this.decodeHtmlEntities(match[1]);
      }
    }

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
      '&nbsp;': ' ',
    };

    return text.replace(/&[^;]+;/g, (entity) => entities[entity] || entity);
  }

  extractNameFromUrl(url) {
    const parts = url.split(/[/\\]/).filter(Boolean);
    return parts[parts.length - 1] || 'unknown-skill';
  }

  parseGitHubUrl(url) {
    const parts = new URL(url).pathname.split('/').filter(Boolean).map(decodeURIComponent);
    const [owner, repoRaw, kind, ref, ...rest] = parts;
    return { owner, repo: repoRaw ? repoRaw.replace(/\.git$/, '') : repoRaw, kind, ref, subPath: rest.join('/') };
  }

  async fetchFromGitHub(url) {
    const { owner, repo, kind, ref, subPath } = this.parseGitHubUrl(url);
    if (!owner || !repo || ((kind === 'tree' || kind === 'blob') && !ref) || (kind === 'blob' && !subPath)) {
      throw new Error(`Unsupported GitHub URL: ${url}`);
    }

    // Repo root, a tree (directory) URL, or a blob URL of a SKILL.md all mean
    // "this skill directory": walk all of it so sibling code is scanned.
    let dir = '';
    if (kind === 'tree') {
      dir = subPath;
    } else if (kind === 'blob') {
      if (path.posix.basename(subPath) !== 'SKILL.md') {
        return this.fetchGitHubSingleFile(owner, repo, ref, subPath, url);
      }
      dir = path.posix.dirname(subPath) === '.' ? '' : path.posix.dirname(subPath);
    } else if (kind) {
      throw new Error(`Unsupported GitHub URL: ${url}`);
    }

    try {
      return await this.fetchGitHubTree(owner, repo, kind ? ref : null, dir, url);
    } catch (error) {
      return this.fetchGitHubManifestOnly(owner, repo, kind ? ref : null, dir, url, error);
    }
  }

  githubRawUrl(owner, repo, ref, filePath) {
    return `https://raw.githubusercontent.com/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/${encodePath(ref)}/${encodePath(filePath)}`;
  }

  async fetchGitHubTree(owner, repo, ref, dir, source) {
    const ctx = this.newContext('GitHubLoader');
    const headers = { Accept: 'application/vnd.github+json' };
    if (process.env.GITHUB_TOKEN) headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
    const api = async (p) => JSON.parse((await fetchBytes(
      `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}${p}`,
      SCAN_LIMITS.maxArchiveBytes, { strict: true, headers })).toString('utf-8'));

    const branch = ref || (await api('')).default_branch;
    const tree = await api(`/git/trees/${encodeURIComponent(branch)}?recursive=1`);

    if (tree.truncated) {
      ctx.add('high', 'GitHub file listing truncated',
        'The repository is too large for GitHub to list completely; some files were NOT scanned.', source);
      ctx.incomplete = true;
    }

    const prefix = dir ? `${dir.replace(/\/+$/, '')}/` : '';
    const nodes = (tree.tree || []).filter((n) => n.path.startsWith(prefix));
    if (nodes.length === 0) {
      throw new Error(`no files found under "${dir || '/'}"`);
    }
    if (nodes.length > SCAN_LIMITS.maxEntries) {
      ctx.add('high', 'Scan limit reached: too many entries',
        `The skill has more than ${SCAN_LIMITS.maxEntries} entries; the rest were NOT scanned.`, source);
      ctx.incomplete = true;
    }

    const candidates = [];
    const flaggedDirs = new Set();
    let symlinkLookups = 0;

    for (const n of nodes.slice(0, SCAN_LIMITS.maxEntries)) {
      const rel = n.path.slice(prefix.length);
      for (const seg of rel.split('/').slice(0, -1)) {
        if (UNUSUAL_DIRS.has(seg) && !flaggedDirs.has(seg)) {
          flaggedDirs.add(seg);
          ctx.add('low', `Unexpected directory in skill: ${seg}`,
            `A skill should not normally ship a ${seg}/ directory; its contents are still scanned but flagged as anomalous.`, rel);
        }
      }

      if (n.type === 'commit') {
        ctx.add('medium', 'Git submodule not scanned',
          `${rel} is a git submodule pointing at another repository; its code was NOT fetched or scanned.`, rel);
        ctx.incomplete = true;
      } else if (n.type === 'blob' && n.mode === '120000') {
        // Symlink: never fetch through it; resolve its target text to classify.
        let target = null;
        if (symlinkLookups++ < SCAN_LIMITS.maxSymlinkLookups) {
          try {
            target = Buffer.from((await api(`/git/blobs/${n.sha}`)).content || '', 'base64').toString('utf-8');
          } catch { /* unresolved: treated as escaping */ }
        }
        const escapes = target === null ||
          escapesRoot(path.posix.normalize(path.posix.join(path.posix.dirname(rel), target)));
        ctx.add(escapes ? 'high' : 'low',
          escapes ? 'Symlink escapes the skill directory' : 'Symlink inside skill (not followed)',
          `${rel} -> ${target ?? '(unresolved)'} is a symbolic link and was NOT followed.`, rel);
      } else if (n.type === 'blob') {
        candidates.push({
          name: path.posix.basename(rel),
          path: rel,
          size: n.size,
          read: async (max) => ({ data: await fetchBytes(this.githubRawUrl(owner, repo, branch, n.path), max), size: n.size }),
        });
      }
    }

    const collected = await this.collect(candidates, ctx);
    return this.finish(collected, ctx, source, path.posix.basename(dir) || repo);
  }

  async fetchGitHubManifestOnly(owner, repo, ref, dir, source, cause) {
    const manifestPath = dir ? `${dir}/SKILL.md` : 'SKILL.md';
    for (const branch of ref ? [ref] : ['main', 'master']) {
      let content;
      try {
        content = (await fetchBytes(this.githubRawUrl(owner, repo, branch, manifestPath), SCAN_LIMITS.maxFileBytes)).toString('utf-8');
      } catch {
        continue;
      }
      const result = this.parseSkillMd(content, source);
      result.loaderFindings.push({
        risk: 'medium',
        title: 'Only SKILL.md was analyzed',
        description: `Could not list the repository (${cause.message}); only the manifest was scanned, so other files in the skill were NOT analyzed. Set GITHUB_TOKEN to avoid API rate limits.`,
        location: source,
        scanner: 'GitHubLoader',
      });
      result.coverage.complete = false;
      return result;
    }
    throw new Error(`No SKILL.md found at ${source} (${cause.message})`);
  }

  async fetchGitHubSingleFile(owner, repo, ref, filePath, source) {
    // An explicit link to one non-manifest file: scan exactly that file.
    const ctx = this.newContext('GitHubLoader');
    ctx.add('low', 'Only a single file was scanned',
      `The URL points at ${filePath}, so only that file was scanned; the rest of the skill was not analyzed. Link the skill directory for full coverage.`, source);
    const collected = await this.collect([{
      name: 'SKILL.md',
      path: 'SKILL.md',
      read: async (max) => {
        // Ask for one extra byte so an oversized file is detected as truncated.
        const data = await fetchBytes(this.githubRawUrl(owner, repo, ref, filePath), max + 1);
        return { data: data.subarray(0, max), size: data.length };
      },
    }], ctx);
    return this.finish(collected, ctx, source, path.posix.basename(filePath));
  }

  async extractZip(filePath) {
    const { size } = await stat(filePath);
    if (size > SCAN_LIMITS.maxArchiveBytes) {
      throw new Error(`Archive is ${size} bytes, over the ${SCAN_LIMITS.maxArchiveBytes}-byte limit; refusing to load it.`);
    }
    return this.parseZipContents(new AdmZip(await readFile(filePath)), filePath);
  }

  async extractZipBuffer(buffer, source) {
    return this.parseZipContents(new AdmZip(buffer), source);
  }

  async parseZipContents(zip, source) {
    const ctx = this.newContext('ZipLoader');
    const entries = zip.getEntries();
    const candidates = [];

    if (entries.length > SCAN_LIMITS.maxEntries) {
      ctx.add('high', 'Scan limit reached: too many entries',
        `The archive has more than ${SCAN_LIMITS.maxEntries} entries; the rest were NOT scanned.`, source);
      ctx.incomplete = true;
    }

    for (const entry of entries.slice(0, SCAN_LIMITS.maxEntries)) {
      if (entry.isDirectory) continue;
      const name = entry.entryName.replace(/\\/g, '/');

      // zip-slip: an entry that escapes the archive root is malicious by
      // construction (no skill needs one); the installer also refuses it.
      if (name.split('/').includes('..') || path.posix.isAbsolute(name) || /^[a-zA-Z]:/.test(name) || name.includes('\u0000')) {
        ctx.add('critical', 'Zip entry escapes archive root (zip-slip)',
          `Archive entry "${name}" uses a traversal or absolute path; extracting it would write outside the skill directory.`, name);
      }

      if (entry.header.encrypted) {
        ctx.add('high', 'Encrypted archive entry',
          `"${name}" is encrypted and could NOT be scanned.`, name);
        ctx.incomplete = true;
        continue;
      }

      const mode = (entry.header.attr >>> 16) & 0o170000;
      if (mode === 0o120000) {
        // Symlink entry: classify its target; it is never extracted or followed.
        let target = '(unreadable)';
        try { target = entry.getData().toString('utf-8'); } catch { /* keep default */ }
        const escapes = escapesRoot(path.posix.normalize(path.posix.join(path.posix.dirname(name), target)));
        ctx.add(escapes ? 'high' : 'low',
          escapes ? 'Symlink escapes the skill directory' : 'Symlink inside skill (not followed)',
          `${name} -> ${target} is a symbolic link and was NOT followed.`, name);
        continue;
      }

      const declared = entry.header.size;
      if (declared > SCAN_LIMITS.maxFileBytes) {
        // adm-zip inflates whole entries; refuse to inflate an oversized one.
        ctx.add('high', 'Archive entry too large to scan',
          `"${name}" declares ${declared} bytes, over the ${SCAN_LIMITS.maxFileBytes}-byte limit; it was NOT scanned.`, name);
        ctx.incomplete = true;
        continue;
      }

      candidates.push({
        name: path.posix.basename(name),
        path: name,
        size: declared,
        read: async (max) => {
          const data = entry.getData(); // bounded by the declared size (adm-zip >= 0.6.1)
          return { data: data.length > max ? data.subarray(0, max) : data, size: Math.max(declared, data.length) };
        },
      });
    }

    const collected = await this.collect(candidates, ctx);
    return this.finish(collected, ctx, source, this.extractNameFromUrl(source));
  }

  parseSkillMd(content, source) {
    const metadata = this.parseSkillMetadata(content);
    const data = Buffer.from(content, 'utf-8');

    return {
      name: metadata.name || this.extractNameFromUrl(source),
      source,
      files: [{
        name: 'SKILL.md',
        path: 'SKILL.md',
        content,
        bytes: data.length,
        truncated: false,
        binary: false,
        magic: null,
        data,
      }],
      metadata,
      rawContent: content,
      loaderFindings: [],
      coverage: { filesScanned: 1, bytesScanned: data.length, truncatedFiles: 0, complete: true },
    };
  }

  parseSkillMetadata(content) {
    const metadata = {};

    // Parse YAML frontmatter
    const frontmatterMatch = content.match(/^---\r?\n([\s\S]*?)\r?\n---/);
    if (frontmatterMatch) {
      try {
        const yamlContent = parseYaml(frontmatterMatch[1]);
        if (yamlContent && typeof yamlContent === 'object') {
          Object.assign(metadata, yamlContent);
        }
      } catch (e) {
        // YAML parse failed, try line-by-line
        this.parseMetadataLines(frontmatterMatch[1], metadata);
      }
    }

    // Also look for table-style metadata (like SkillsMP format). Keys are
    // explicit: deriving them from `pattern.source` returned null and crashed
    // the scan of any skill containing a `| name |` table.
    const tablePatterns = {
      name: /\|\s*name\s*\|\s*([^|]+)\|/i,
      description: /\|\s*description\s*\|\s*([^|]+)\|/i,
      'allowed-tools': /\|\s*allowed-tools\s*\|\s*([^|]+)\|/i,
      author: /\|\s*author\s*\|\s*([^|]+)\|/i,
    };

    // Frontmatter is authoritative (it is what Claude Code reads), so a table
    // only fills keys the frontmatter did not provide.
    const tableMatch = content.match(/\|\s*name\s*\|/i);
    if (tableMatch) {
      for (const [key, pattern] of Object.entries(tablePatterns)) {
        const match = content.match(pattern);
        if (match && metadata[key] === undefined) {
          metadata[key] = match[1].trim();
        }
      }
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
