# CLAUDE.md

Rules for Claude Code sessions working in this repository. Personal paths and
workflow belong in a gitignored `CLAUDE.local.md` beside this file, not here.

## Changes and commits

- Show the full diff for review before committing. Nothing is committed until
  the maintainer approves it.
- Every commit is a release. Bump `$EntraAccessAuditVersion` in
  `Invoke-EntraAccessAudit.ps1`, add a line to the version notes in its header,
  and add an entry to the README changelog. Then push.
- Commit messages start with `v<version>: <summary>` and are followed by a
  bulleted body describing each change.
- When asking for approval, make the approve option specific and keep the
  "I want changes" option neutral. Don't pre-scope the answer.

## Signing and releases

- Commits and tags must be signed, because GitHub vigilant mode is on. An
  unsigned commit shows as Unverified. A session that can't sign with the
  maintainer's key prepares changes on a branch, and the signed release is done
  where the key is.
- Chain commit, tag and push so a failed step stops the rest (`set -e`). A
  failed commit must not leave a stray tag behind.
- Sign tags with `git tag -s v<version>`. Create a Release only from the
  existing tag: `gh release create v<version> --verify-tag`.
- After pushing, check every job in the Tests workflow (Pester suite, lint on
  5.1, lint on 7) and report each result.

## Read-only

- The audit never changes a tenant. Every Graph call goes through
  `Invoke-AuditGraphRequest`, which sends GET only, and the scopes in
  `$AuditScopes` are all `.Read.` scopes. Tests in `tests/Collector.Tests.ps1`
  enforce both. Don't add a write call, a write scope or a Graph cmdlet that
  changes anything.
- Ask for the least privilege that works. A new dataset uses a scope already in
  `$AuditScopes` where one covers it; a new scope needs the maintainer's
  approval and a README update.

## Testing

- The audit supports Windows PowerShell 5.1 and PowerShell 7, and a pass on one
  says nothing about the other. Before every commit, run both of these:
  - `.\Test-EntraAccessAudit.ps1 -BothEditions`
  - `.\Test-EntraAccessAuditLint.ps1 -BothEditions`
- Lint fails only on Error, Warning or ParseError. Suppress a rule only with a
  `SuppressMessageAttribute` on the function, with a justification, or in
  `PSScriptAnalyzerSettings.psd1` with a comment saying why.
- Run `actionlint` whenever a file under `.github/workflows/` changes.
- A silent pass is the worst outcome. Checks whose data wasn't collected are
  Skipped and counted, never passed vacuously.
- Checks read only the snapshot, never the tenant, so every rule is testable
  without one. A new check gets a Fail or Warn case, a Pass case and a Skipped
  case in `tests/Checks.Tests.ps1`, and a row in the README's check table.
- Add a regression case for every bug fixed.
- Graph dates arrive as strings on 5.1 and DateTime on 7 after
  `ConvertFrom-Json`. Read them with `ConvertTo-UtcDate`, and judge them
  against the snapshot's `CollectedAt`, never the clock.

## PowerShell traps

- A one-item array unwraps on return. Wrap the result with `@(...)` where a
  list is expected.
- Variable names aren't case-sensitive (`$V` and `$v` are the same variable).
  Avoid names that collide with built-in aliases, such as `R`.
- An array passed through `pwsh -File` arrives as one string.
- `-replace` replaces every match. Anchor the pattern when a file contains
  repeats, such as markup inside a script string.
- Strict mode is on: read optional properties with `Get-Value`, which returns
  `$null` for a missing one.
- Never leave a catch block empty. Log a reason, at least with
  `Write-Verbose`.
- Never put an ambient-state lookup in a parameter default.

## Privacy

This repository is public. Tracked files must not contain:

- real tenant IDs, app IDs, object IDs, domains, user names, guest names or
  employers (the fixtures use the fictional tenant Westmark, domain
  `westmark.example`, and IDs of the form `00000000-0000-4000-8000-...`);
  Microsoft's own well-known IDs, such as built-in role template IDs and the
  Microsoft Graph app ID, are fine
- reports or snapshots from real tenants
- personal paths, email addresses, or third-person references to the maintainer

Personal settings live in gitignored files: `EntraAccessAudit.local*.psd1` and
`*.local*.md`. Reports (`Reports/`, `entra-access-audit-*`) and snapshots
(`*.snapshot.json`, except the fixtures) are gitignored too. Never stage any of
them. Confirm that they are absent from the diff, not just ignored.

Before pushing, grep the diff for these patterns and report a count for each,
rather than declaring the diff clean.
