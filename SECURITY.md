# Security policy

## Supported versions

Fixes go into the latest release only.

## What it does to a tenant

Nothing. The audit is read-only. Every request it sends to Microsoft Graph is a
GET, through one function, and it asks only for read scopes:
`User.Read.All`, `AuditLog.Read.All`, `RoleManagement.Read.Directory`,
`Application.Read.All`, `Policy.Read.All`, `DelegatedPermissionGrant.Read.All`,
`GroupMember.Read.All` and `Organization.Read.All`.

It writes only its own report files, and a snapshot when `-SnapshotPath` is
given. Both name real accounts, guests and apps, so keep them somewhere private.

## What to report

The tool promises to change nothing in a tenant and to report only what it can
show evidence for, so report anything that could break either promise, for
example:

- a code path that sends anything other than a GET to Microsoft Graph, or asks
  for a scope that can write;
- a way for a snapshot or thresholds file to run code (both are meant to be
  data only);
- a way for tenant data, such as an app or user name, to inject script or
  markup into the HTML report;
- a check that reports Pass without the evidence to back it;
- a vulnerability in a GitHub Action the workflow uses.

## How to report

Use **Report a vulnerability** on this repository's **Security** tab, which
opens a private advisory only the maintainer can see. Please don't open a public
issue for a security problem.

Include what you found, how to reproduce it, and which version you tested
(`$EntraAccessAuditVersion` in `Invoke-EntraAccessAudit.ps1`, or the release
tag).

## What to expect

This project has one maintainer, so responses are best effort.
