import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const pkg = JSON.parse(readFileSync(path.join(root, 'package.json'), 'utf-8'));
const bins = Object.entries(pkg.bin);

// `npx <name>` runs the bin named after the package. Without that entry npm
// aborts with "could not determine executable to run", which is exactly what
// the READMEs' documented `npx claude-skill-antivirus` did up to 2.2.0.
test('a bin is named after the package, so `npx claude-skill-antivirus` resolves', () => {
  assert.ok(pkg.bin[pkg.name], `package.json bin must declare "${pkg.name}"`);
});

for (const [name, target] of bins) {
  test(`bin ${name} resolves and runs --version`, () => {
    const file = path.join(root, target);
    assert.match(readFileSync(file, 'utf-8'), /^#!\/usr\/bin\/env node\r?\n/, 'bin needs a node shebang');
    const stdout = execFileSync(process.execPath, [file, '--version'], { encoding: 'utf-8' });
    assert.equal(stdout.trim(), pkg.version);
  });
}

test('every bin ships in the published tarball', () => {
  const [{ files }] = JSON.parse(
    execFileSync('npm', ['pack', '--dry-run', '--json'], {
      cwd: root,
      encoding: 'utf-8',
      stdio: ['ignore', 'pipe', 'ignore'],
    })
  );
  const packed = new Set(files.map((entry) => entry.path));
  for (const [name, target] of bins) {
    assert.ok(packed.has(target), `bin ${name} -> ${target} is excluded by "files"`);
  }
});
