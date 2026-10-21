import { readFileSync } from 'node:fs';

/**
 * Single source of truth for the package version.
 * Read from package.json at runtime so the CLI banner, `--version`, and the
 * batch scanner can never drift out of sync with the published version again
 * (the root cause of the 2.1.1/2.1.2/2.1.3 patch churn).
 */
export const VERSION = JSON.parse(
  readFileSync(new URL('../package.json', import.meta.url), 'utf-8')
).version;
