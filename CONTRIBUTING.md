# Contributing

Thanks for your interest in improving mikebom-harbor-adapter.

## Development workflow

1. Fork and branch from `main`.
2. Install tools and git hooks: `task setup`.
3. Make your change. Keep commits focused.
4. Run the local gates before pushing:
   - `task build`
   - `task test`
   - `task lint:local`
   - `task lint:yaml`
   - `task vuln-check`
5. Open a pull request.

## Commit and PR conventions

- **Conventional Commits** are required. Types: `feat`, `fix`, `docs`, `style`,
  `refactor`, `perf`, `test`, `build`, `ci`, `chore`, `revert`. The PR title is
  validated and becomes the squashed commit message.
- **Squash merge only.** Merge commits break release-please changelog parsing.
- **DCO sign-off** is required on every commit: `git commit -s`.
- No AI attribution trailers, no `Co-Authored-By` from tools.

## Releases

Releases are automated by [release-please](https://github.com/googleapis/release-please).

- Never push `v*` tags manually. release-please opens a release PR; merging it
  tags the release and triggers the image publish.
- **`exclude-paths` gotcha:** commits touching only `.github/` or `docs/` do not
  bump the version, even as `feat:`/`fix:`. Use `ci:`/`docs:` types there.
- A mikebom pin bump (`versions.env`) ships as `fix:` so it releases as a patch.

## Security

Report vulnerabilities privately (see [SECURITY.md](SECURITY.md)). Do not open a
public issue for a security report.
