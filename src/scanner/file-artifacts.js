/**
 * FileArtifactScanner - Flags non-text artifacts that have no place in a skill.
 *
 * Text engines can only read strings. A compiled or native artifact
 * (.pyc, .so, .node, .dll, an executable, an archive) is opaque to them and is
 * exactly where a payload hides (issue #33: a poisoned `__pycache__/*.pyc`), so
 * the presence of the artifact is itself a finding, independent of any string
 * the other engines happen to surface from it. Files are identified by their
 * leading bytes as well as their extension, so renaming an executable to
 * `notes.txt` does not hide it.
 */
export class FileArtifactScanner {
  constructor() {
    // Compiled bytecode / native code: high risk, cannot be reviewed as text.
    this.compiledExts = new Set([
      '.pyc', '.pyo', '.pyd', '.so', '.node', '.dll', '.dylib', '.exe', '.msi',
      '.class', '.o', '.a', '.lib', '.wasm', '.bin', '.out', '.elf',
    ]);
    // Bundled archives can smuggle further files past review: medium risk.
    this.archiveExts = new Set([
      '.zip', '.tar', '.gz', '.tgz', '.bz2', '.xz', '.7z', '.rar',
      '.jar', '.war', '.whl', '.egg', '.deb', '.rpm', '.dmg', '.pkg', '.apk',
    ]);
  }

  async scan(skillContent) {
    const findings = { critical: [], high: [], medium: [], low: [], info: [] };
    const files = skillContent.files || [];
    let nonText = 0;
    let media = 0;
    let vcsObjects = 0;

    for (const file of files) {
      const p = (file.path || file.name || '').toLowerCase();
      const base = p.slice(p.lastIndexOf('/') + 1);
      const dot = base.lastIndexOf('.');
      const ext = dot > 0 ? base.slice(dot) : '';
      const detected = file.magicType ? ` (detected: ${file.magicType})` : '';

      if (file.vcsObject) {
        vcsObjects++;
        continue;
      }

      if (file.pycUnchecked) {
        findings.critical.push({
          title: 'Unchecked hash-based .pyc (PEP 552)',
          description: `${file.path} is compiled Python bytecode marked UNCHECKED_HASH: Python imports it without ever comparing it to the .py source, so the reviewable source can be a decoy. This is the technique from issue #33.`,
          location: file.path,
          scanner: 'FileArtifactScanner',
        });
      }

      if (this.compiledExts.has(ext) || file.magic === 'executable' || file.magic === 'bytecode') {
        nonText++;
        const disguised = !this.compiledExts.has(ext) ? ` It is named as "${ext || 'no extension'}" but its bytes say otherwise.` : '';
        findings.high.push({
          title: 'Compiled/native artifact in skill',
          description: `${file.path} is a compiled or native binary${detected}. Its code cannot be reviewed as text and is a common place to hide a payload (e.g. a poisoned .pyc).${disguised} Remove it or ship reviewable source.`,
          location: file.path,
          scanner: 'FileArtifactScanner',
        });
      } else if (this.archiveExts.has(ext) || file.magic === 'archive') {
        nonText++;
        findings.medium.push({
          title: 'Bundled archive in skill',
          description: `${file.path} is an archive${detected} that can smuggle additional files past review. Unpack it and ship reviewable files instead.`,
          location: file.path,
          scanner: 'FileArtifactScanner',
        });
      } else if (file.magic === 'media') {
        media++;
      } else if (file.binary) {
        nonText++;
        findings.medium.push({
          title: 'Binary (non-text) file in skill',
          description: `${file.path} contains unrecognized binary data. Only its readable strings were scanned; binary content cannot be fully analyzed.`,
          location: file.path,
          scanner: 'FileArtifactScanner',
        });
      }
    }

    if (files.length > 0) {
      const coverage = skillContent.coverage;
      const extras = [
        nonText ? `${nonText} non-text artifact(s)` : '',
        media ? `${media} media/font file(s)` : '',
        vcsObjects ? `${vcsObjects} git object-storage file(s)` : '',
      ].filter(Boolean).join(', ');
      findings.info.push({
        title: `Files analyzed: ${files.length}${coverage ? `, ${coverage.bytesScanned} bytes` : ''}`,
        description: `Scanned ${files.length} file(s)${extras ? ` including ${extras}` : ''}.`,
        scanner: 'FileArtifactScanner',
      });
    }

    return findings;
  }
}
