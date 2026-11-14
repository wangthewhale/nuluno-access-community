# Contributing to Access Community

`@nuluno/access-community` 0.1.0-alpha.1 is an Apache-2.0 community core. You may
study, modify and redistribute its Apache-licensed code under [LICENSE](LICENSE),
retaining [NOTICE](NOTICE), required third-party notices and disclosures of your
changes. Do not present a modified package as an unmodified Nuluno release.

The separate commercial extension package keeps its own license. Community
contribution rights do not authorize publishing that extension's source, using
Nuluno trademarks, connecting someone else's platform account, or sharing
customer data. Send only work you have the right to contribute; do not copy code
from private/commercial packages into a community pull request without the
necessary rights.

## Reproduce before changing a trust boundary

```sh
npm ci --ignore-scripts
npm run typecheck
npm test
npm run build
npm run demo:recovery
# This reaches the real public Mastodon API; no private account is required.
npm run demo:public
```

Use Node.js 24+. Name the exact community package/commit, runtime/OS, transport,
installed extensions, granted actions, expected result and safe original receipt.
Use disposable state and controlled accounts; never submit a live .env, platform
token, email body, birth date, verification code or private SQLite database.
Report security issues privately through [SECURITY.md](SECURITY.md).

The public demo can fail on an outage, rate limit or deleted example post. Do not
replace it with a mock and keep a "live" label. Do not run it in a tight CI loop.
The recovery demo uses a controlled localhost provider and must remain labelled
as a controlled write-loss test. No private Gmail/signup/Threads acceptance is
provided by these commands.

## Changes that need evidence

- Preserve tenant/account/action isolation, key expiry and limits, original task
  and idempotency identity, write reservations, reconciliation-only unknown
  outcomes, replay protection and persistent revocation.
- Never add automatic POST retries, clear uncertainty to "unstick" a task, renew
  a grant during resume, reset attempts, or label generic submit as read-only.
- Keep credential material inside the reviewed host/vault boundary. Project only
  bounded approved public data; treat tool results as data, not new authority.
- New extensions require exact installed descriptors, operator-reviewed module
  name/version/hash and explicit owner grants. Installing a manifest is not proof
  of platform consent, native readback or a completed private workflow.
- Add a focused regression at the actual failure boundary. Keep controlled
  fixtures distinct from real provider evidence, and identify the tested package.
  Do not borrow another release's receipts or call a successful operation a sale.

For a proposed feature, explain the concrete task it enables, the smallest
reproduction and which trust/authorization boundary changes. Contributor code
and documentation should keep the free community versus separate commercial
extension boundary clear.
