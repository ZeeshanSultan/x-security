# Changelog

Notable changes to the `x-security` toolkit and its published CLI
[`@chain305/x-security`](https://www.npmjs.com/package/@chain305/x-security).
Format follows [Keep a Changelog](https://keepachangelog.com/). Pre-1.0, a
breaking change bumps the minor version.

## [0.4.1] — 2026-07-08

### Fixed
- Install and usage docs still showed the old `xsecurity` command while the
  binary was already `x-security`, so a copy-pasted command failed. Unified all
  docs, help text, and examples to `x-security`.
- `config/defaults.ts` now searches `~/.config/x-security/` and `.x-securityrc*`
  first, keeping the legacy `xsecurity` / `.xsecurityrc` paths as a fallback so
  pre-rename configs still load.
- Reconciled the `push` command tests to `X_SECURITY_API_TOKEN` (dropped the
  stale `WRIT_API_TOKEN` legacy assertions).

## [0.4.0] — 2026-07-08

### Changed — BREAKING
- **The CLI command is renamed to `x-security`.** Previously the command was
  `lazy` (internal dev builds) and `xsecurity` (npm). Any script, CI job, or
  muscle-memory invoking the old names must switch to `x-security`. No flags,
  subcommands, or runtime behavior changed — only the command name.
- Existing `lazy` / `xsecurity` installs break on upgrade (intended).

```
npm i -g @chain305/x-security
x-security --help
```

Not renamed (separate namespaces): the `/lazy-scan` Claude Code plugin command
and the retired `lazy.chain305.com` redirect host.

## [0.3.1] and earlier

Published under the `xsecurity` command. These versions are deprecated on npm in
favor of `x-security` (0.4.0+).
