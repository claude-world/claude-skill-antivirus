# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.2.1] - 2026-10-21

### Fixed
- **`npx claude-skill-antivirus <skill-source>` works again.** The package declared the bins `skill-install`, `claude-skill-av` and `skill-batch-scan`, none matching the package name, so the command both READMEs document failed with `npm error could not determine executable to run`. `claude-skill-antivirus` is now a bin alias for the installer; the other three names are unchanged. Broken since at least 2.1.3, which means 2.2.0's #33 security fix was unreachable through the documented entry point.
- `--help` reports the alias that was actually invoked instead of always printing `skill-install`.

### Changed
- npm publishing uses [trusted publishing](https://docs.npmjs.com/trusted-publishers) (OIDC) instead of an `NPM_TOKEN` secret: the workflow requests `id-token: write`, runs on Node 24 (trusted publishing requires npm >= 11.5.1, and Node 22 still bundles npm 10.9.x), and asserts the npm version before publishing. Releases now carry provenance attestations, which npm generates automatically for this path.
- The publish workflow gained a `workflow_dispatch` trigger, so a publish can be retried without cutting a new release.

### Added
- `test/bin.test.js`: every bin in `package.json` must resolve, carry a node shebang, print the package version for `--version`, and be present in the published tarball.

## [2.2.0] - 2026-10-21

### Security
- **Fixed [#33](https://github.com/claude-world/claude-skill-antivirus/issues/33): only `SKILL.md` was analyzed.** The scanner now walks the entire skill directory, so hidden code in `scripts/`, nested folders, or a poisoned `__pycache__/*.pyc` is scanned by every engine instead of scoring a false `SAFE 100/100`. Reported by [@nedlir](https://github.com/nedlir); directory-walk foundation contributed by [@Yahhi](https://github.com/Yahhi) in [#34](https://github.com/claude-world/claude-skill-antivirus/pull/34).
- The manifest-only bypass is closed on every input path: a bare `SKILL.md` path scans its siblings; GitHub repository, `tree/` and `blob/.../SKILL.md` URLs walk the skill directory through the GitHub API; manifest-only fallbacks (SkillsMP page scrape, API rate limit, batch catalog scan) are reported as findings and can never read as SAFE.
- Directories such as `node_modules`, `.git`, `venv` and `__pycache__` are scanned and flagged, never silently skipped.
- Symlinks are never followed; one that leaves the skill root is a HIGH finding. GitHub submodules (code that is not fetched) are reported.
- Compiled, native and archive artifacts are findings in their own right and are identified by magic bytes, so a renamed executable is still caught. A PEP 552 *unchecked-hash* `.pyc` (Python loads it without checking the source, the #33 technique) is CRITICAL.
- Scan limits (2 MB per file, 16 MB / 2000 files per skill) are enforced with bounded reads; truncation, unread files and limit hits are reported as findings. The manifest is read first and then the smallest files, so padding cannot exhaust the budget before the code.
- Installer: refuses zip-slip paths that would write outside the skill directory, refuses skills that were not fully scanned, writes exact bytes (binaries were re-encoded as UTF-8), never installs VCS metadata, and no longer installs straight into the shared skills directory when a name sanitizes to empty.
- `.zip` inputs: traversal/absolute entry names are CRITICAL; encrypted, oversized and symlink entries are reported; archive size is capped.
- Fixed ReDoS across the engines: unbounded wildcard gaps let a crafted long line hang the scanner; every gap is now bounded.

### Fixed
- Scanning a `SKILL.md` that contains a markdown table with a `name` column crashed (`Cannot read properties of null`); frontmatter now stays authoritative over table metadata.
- Pattern precision now that real code is scanned: `.env`/`.key` no longer match `os.environ`/`.keys()`; `nc` no longer matches inside `async`; internal-IP checks require full dotted quads (not `3.10.4`); the cloud-metadata heuristic needs a metadata endpoint, not the word "metadata"; a plain `file://` reference (e.g. an MCP resource URI) is MEDIUM, while `file://` handed to a fetcher or aimed at system files stays CRITICAL.
- Compound "behavior" heuristics are judged per file; signals that only co-occur across different files are still reported, at MEDIUM and marked "(across files)".
- SkillsMP archive downloads used the removed `response.buffer()` API.

### Added
- **File Artifact Scanner** (10th engine).
- `examples/hidden-code-skill/` demonstrating the #33 bypass class (inert fixture).
- Regression test suite under `test/` (`node --test`), with all fixtures generated inert at runtime.
- Programmatic API entry `src/lib.js` (`SecurityScanner`, `loadSkill`, `SCAN_LIMITS`, ...) with no CLI side effects, fixing the documented `import` example.
- Optional `GITHUB_TOKEN` for GitHub API rate limits.

### Changed
- Skills that ship scripts now surface the existing engines' findings for that code as well, so expect more findings than in 2.1.x and review them.
- Node.js requirement raised to **>= 22** (required by commander 15 and chalk 6; Node 20 is end-of-life).
- Upgraded dependencies: adm-zip 0.6.1 (clears 8 high-severity advisories), chalk 6, commander 15, inquirer 14, ora 9, yaml 2.9; removed `node-fetch` in favor of the built-in `fetch`.
- Version is read from `package.json` at runtime (single source of truth), preventing the CLI-banner/`--version` drift behind 2.1.1-2.1.3.
- CI tests Node 22/24/26 and audits dependencies; GitHub Actions bumped to current majors; Dependabot groups minor+patch updates monthly.
- Documentation updated for Claude Code Opus 5.5 / Sonnet 5.5 / Haiku 5.5 / Fable 5.1.

## [2.1.3] - 2026-04-04

### Fixed
- CLI banner now shows correct version (was displaying `v2.0.0`)
- GitHub repo root URLs now work with `--scan-only` (e.g. `skill-install https://github.com/user/repo --scan-only`)

### Changed
- Bumped dependencies: commander 14.0.3, yaml 2.8.3
- Bumped CI actions: checkout v6, setup-node v6, codeql-action v4

## [2.1.1] - 2026-03-14

### Fixed
- CLI `--version` flag now shows correct version (was displaying `2.0.1` instead of current version)

### Added
- CHANGELOG.md documenting full release history

## [2.1.0] - 2026-03-13

### Added
- CONTRIBUTING.md with contribution guidelines (#6)
- Issue and PR templates (#6)
- GIF demo placeholder in README (#5)
- CI/CD automated testing workflow via GitHub Actions (#7)

### Changed
- Updated README for Opus 4.6 compatibility
- Added badges to README

## [2.0.1] - 2026-01-19

### Fixed
- Handle array format in `allowed-tools` permission parsing

### Changed
- Separated capability warnings from actual threats in permissions scanner

### Added
- GitHub Actions CI workflow for testing

## [2.0.0] - 2026-01-19

### Added
- 4 new security scanner engines (total: 9 engines)
- i18n support (English and zh-TW)
- Batch scanner for scanning multiple skills
- SkillsMP integration with scan reports

## [1.0.0] - 2026-01-18

### Added
- Initial release of Claude Skill Antivirus
- 5 core security scanner engines
- CLI tool for scanning Claude Code Skills
- Risk scoring system (0-100)
- Risk level classification (SAFE, LOW, MEDIUM, HIGH, CRITICAL)
- Support for local files and remote URLs
- Interactive installation confirmation prompts
- Global and project-level installation support

[2.2.1]: https://github.com/claude-world/claude-skill-antivirus/compare/v2.2.0...v2.2.1
[2.2.0]: https://github.com/claude-world/claude-skill-antivirus/compare/v2.1.3...v2.2.0
[2.1.3]: https://github.com/claude-world/claude-skill-antivirus/compare/v2.1.1...v2.1.3
[2.1.1]: https://github.com/claude-world/claude-skill-antivirus/compare/v2.1.0...v2.1.1
[2.1.0]: https://github.com/claude-world/claude-skill-antivirus/compare/v2.0.1...v2.1.0
[2.0.1]: https://github.com/claude-world/claude-skill-antivirus/compare/v2.0.0...v2.0.1
[2.0.0]: https://github.com/claude-world/claude-skill-antivirus/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/claude-world/claude-skill-antivirus/releases/tag/v1.0.0
