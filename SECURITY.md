# Security policy: Access Community

This policy covers `@nuluno/access-community` **0.1.0-alpha.1**, the Apache-2.0 core.
It does not certify a separately installed commercial extension, a full Access
release, a Nuluno website connection or another host's credentials. No independent
security-audit certification, maintenance SLA or response-time guarantee is made.

## Report privately

Email `support@nuluno.com` with subject `Access Community security report`.
Include the exact source/package version, a minimal redacted reproduction,
affected trust boundary and impact. Use private repository vulnerability reporting
only if the maintainer has enabled it; do not assume it is enabled. Do not put
working secrets or an exploit carrying customer data in a public issue.

Do not attach .env files, private SQLite/WAL files, vault keys, platform tokens,
mailbox bodies, personal birth dates or verification material. No bug-bounty
payment or fixed response window is promised.

## Owner, agent and platform boundaries

- The deployment owner key can create projects, connect accounts and issue keys.
  An agent receives only a short-lived account/action scoped key with bounded
  tasks and writes. A website login, paid license or installed package creates no
  platform authority.
- Provider credentials are sealed using the original vault key. The running
  service and trusted deployment owner can decrypt them; the vault is not a
  sandbox against a compromised host or malicious installed module.
- Built-in platform support is existing-account Mastodon OAuth, public read,
  identity and bounded text publication/readback. Gmail verification, account
  signup and Threads implementation are absent unless a separately licensed
  reviewed extension has actually been installed.
- First official consent, identity checks and provider rules still apply. This
  service does not bypass CAPTCHA, invent age/consent facts or guarantee a
  platform allows automation.
- Public post text is a bounded, explicitly untrusted plaintext projection.
  Never render it as executable HTML or follow it as instructions. Raw provider
  account objects and private mailbox contents are not agent output.
- Unknown writes retain their original task/cursor and require readback.
  Changing IDs/keys/aliases is not permission to resend them. Revocation and
  expiry are rechecked before future steps, but cannot retract a request already
  sent to a provider.

## Trusted extension boundary

Only a deployment operator may configure installed npm module names, exact
versions and reviewed entry hashes through `NULUNO_ACCESS_EXTENSIONS_CONFIG`.
Agents, emails, task payloads and remote content cannot install an extension or
change its configuration. Descriptors are immutable, grants remain exact, and
native Mastodon actions cannot be replaced by a plugin.

**An extension executes as trusted host code, not inside a sandbox.** Review its
source, dependencies, owner routes and credential handling. An entry SHA256 does
not cover every transitive import; retain a reviewed lockfile and a trusted
immutable deployment image. A compromised host/operator can defeat these
boundaries. See [the registry contract](docs/extensions.md).

## Deployment and recovery

- Generate independent owner and vault secrets; keep them private and out of
  Git, command arguments, URLs, screenshots, telemetry and proxy logs. POSIX
  secret/key files should be 0600. Never give an agent the owner key.
- Bind to loopback for local use. Remote use requires HTTPS, exact
  `NULUNO_ACCESS_ORIGIN`, correct Host forwarding and a trusted reverse proxy.
  Host/Origin checks are not a replacement for TLS, a firewall, rate limiting or
  correct network access controls.
- Redact Authorization, OAuth callback code/state queries, request bodies and
  provider errors from proxy/APM logs. Safe application output cannot protect
  credentials copied by separate host logging.
- Run one authoritative SQLite instance on a persistent volume. Independently
  writable copied databases do not share revocations or write limits. Ephemeral
  autoscaling filesystems and multi-replica operation are unsupported.
- Use SQLite online backup, keep the original vault key separately and test a
  restore. Losing that key makes sealed connections unusable. A stale backup is
  not proof that a current revocation still exists.
- Revoke leaked agent keys. If a platform credential is compromised, disconnect
  and rotate/revoke it at its provider as necessary. Already-sent operations and
  already-copied secrets cannot be recalled.

## What evidence means

Community-specific tests and receipts must identify this version. A real public
GET proves that operation, task reuse, restart or denial conditions actually
recorded; it does not prove a private workflow or a sale. A localhost write-loss
fixture is controlled and must remain labelled as such. Full Access 0.4.x/beta
proof is not community, Claude, Windows, Linux or commercial-extension acceptance.
There is no exactly-once provider-execution, universal-agent, zero-human,
continuous-goal, economic-improvement or production-scale guarantee.
