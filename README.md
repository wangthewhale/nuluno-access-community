# Nuluno Access Community

**Give an agent a limited key. Keep platform credentials in your service.**

I built Access because connecting an agent should not mean handing it every
credential or starting the same external operation again after a restart.
Access stores credentials in an encrypted vault, issues scoped agent keys,
keeps original tasks and reconciles uncertain writes. You can revoke future
operations without giving the agent a replacement key.

The free Apache-2.0 core runs on your own host. Standard MCP, REST and the
JavaScript SDK use the same durable service and task identities.

## First run: read one real public status

Requires **Node 24+**. This example needs no Nuluno account, model API key or
social login. Use a new source checkout:

```sh
git clone https://github.com/wangthewhale/nuluno-access-community.git
cd nuluno-access-community
npm ci --ignore-scripts
npm run build
node examples/public-status/read-once.mjs --out my-public-status
```

Open **`my-public-status/status.md`**. It contains a real public Mastodon status
with its URL and original task/receipt IDs. The service creates a zero-write key
for exactly that public provider, then uses the official MCP client and SDK.
Public text is bounded and labelled as untrusted data.

Run the last command again. A new service process returns the same original
task and receipt with one provider call reserved. Private owner keys, agent
keys, vault key and SQLite state remain in the Git-ignored output folder.
[Commands and recovery details](examples/public-status/README.md).

## Three things to try

| Situation | Useful action | What you can verify |
|---|---|---|
| An agent needs a public social source | Save one status into a local notebook | Native public data, bounded text and a source receipt |
| A client restarts or changes transport | Reuse the same idempotency key through MCP and SDK | Same task and receipt, no new reserved provider call |
| An agent should lose access | Add `--revoke` to the same command | Its original key is denied after another service restart |

The [version-bound alpha.2 Linux receipt](docs/evidence/first-use-0.1.0-alpha.2-20261115.json) records the exact source commit, a real public GET, original-task/receipt reuse through MCP and SDK after restarting the service, original-key revocation and a later fresh process exiting with code 3. The [preceding preflight](docs/evidence/first-use-preflight-20261115.json) remains unchanged. These are operator-run technical checks, not an outside human trial, private-account signup/publication acceptance or sales improvement. Linux core CI also started a real container and preserved state across two restarts.

## What you can connect

| Included in this community core | Separate commercial extension |
|---|---|
| Scoped keys, quotas, expiry, revocation and encrypted vault | Gmail verification reader/consumer |
| Durable tasks and uncertain-write reconciliation | Account-signup pipeline |
| MCP, REST and JavaScript SDK | Threads connector |
| Public Mastodon reads; official OAuth and bounded posting for an existing Mastodon account | Other advanced connectors when installed and authorized |

Connecting a private existing account still requires the owner's official
consent. An extension or paid license does not supply that consent. CAPTCHA and
provider-required identity steps keep an explicit handoff. No universal login
bypass or uninterrupted private workflow is promised.

This is **`@nuluno/access-community` 0.1.0-alpha.2**, an independent,
single-instance SQLite service. Public remote deployment needs HTTPS, retained
state and the original vault key. The package name does not imply an npm
registry release or a managed cloud subscription. Full Access releases retain
their own license and evidence.

## Connect your agent and keep control

The core exposes `/.well-known/nuluno-access.json` and `/mcp`, with an optional
stdio bridge. Each agent receives its own limited Bearer key, not the deployment
owner key or provider token. Follow the [setup and SDK guide](docs/technical-guide.md)
to use a persistent service or connect your existing Mastodon account.

Revocation blocks future access; it cannot unsend a request or erase data an
agent already received. Complete costs remain unknown where bills are missing.
No fixed savings, sales lift or universal client compatibility is claimed.

If your first task fails, open a [first-run issue](https://github.com/wangthewhale/nuluno-access-community/issues/new/choose)
with runtime versions and a sanitized receipt. Never attach state folders,
keys, inbox contents or customer data. The example sends no telemetry.

[Technical guide](docs/technical-guide.md) · [Extension contract](docs/extensions.md) ·
[Security](SECURITY.md) · [Contributing](CONTRIBUTING.md) · [License](LICENSE)

## Client identity and authorization

The SDK identifies its actual Nuluno Community version. A confirmed Cloudflare 403 / Error 1010 is reported as `transport_client_identity_rejected` with `requiresOwnerAuthorization: false`; it is a transport identity problem. Structured invalid-key, revoked-key and scope-denial responses remain authorization failures. This classification never renews a key, expands a grant or retries a possibly dispatched POST.
