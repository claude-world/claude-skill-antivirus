# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[2.1.1]: https://github.com/claude-world/claude-skill-antivirus/compare/v2.1.0...v2.1.1
[2.1.0]: https://github.com/claude-world/claude-skill-antivirus/compare/v2.0.1...v2.1.0
[2.0.1]: https://github.com/claude-world/claude-skill-antivirus/compare/v2.0.0...v2.0.1
[2.0.0]: https://github.com/claude-world/claude-skill-antivirus/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/claude-world/claude-skill-antivirus/releases/tag/v1.0.0
