# Contributing

Thanks for contributing to Claude Skill Antivirus.

## How to Report Bugs

- Check existing issues before opening a new one.
- Share a minimal reproduction, expected behavior, actual behavior, and any relevant logs.
- Include your environment details, especially OS, Node.js version, and package version.
- Do not paste secrets, tokens, or private skill content.

## How to Suggest Features

- Search existing issues and feature requests first.
- Describe the problem you want to solve, not just the proposed solution.
- Explain the expected user impact, scope, and any CLI or scanning behavior changes.

## Development Setup

1. Fork and clone the repository.
2. Install Node.js 18 or later.
3. Run `npm install`.
4. Run `npm test`.
5. For manual checks, run `node src/index.js ./examples/safe-skill --scan-only`.

## Code Style

- Use modern ESM JavaScript with semicolons and 2-space indentation.
- Keep scanner logic focused, readable, and consistent with existing module structure.
- Update user-facing strings in `src/i18n/` when changing CLI output.
- Keep changes small and directly related to the issue or feature.

## PR Process

- Create a focused branch for each change.
- Link the related issue in the PR description when applicable.
- Summarize what changed and how you tested it.
- Update docs or examples when behavior changes.
- Wait for review and CI before merging.
