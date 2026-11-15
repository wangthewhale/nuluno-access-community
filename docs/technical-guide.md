# Nuluno Access Community

**Free Apache-2.0 core for scoped agent access, durable tasks and revocation.**

An owner connects an existing Mastodon account and issues a limited agent key.
Access keeps platform credentials in its encrypted vault, saves original tasks,
reconciles uncertain writes, and checks revocation before future external steps.
It runs independently of Nuluno.com and Nuluno Engine.

**Version: `@nuluno/access-community` 0.1.0-alpha.2.** This is an alpha community
package, distinct from the separately licensed full Access releases. Its own
package, source and execution receipts must be used when assessing it. A package
name does not imply that an npm registry release or a hosted service is available.

## What is free, and what is separate

| Capability | Community package |
|---|---|
| Broker, tenant/account/action scoped keys, limits, expiry and revocation | Included |
| Encrypted credential vault, single-instance SQLite, durable original tasks | Included |
| Unknown-write isolation, reconciliation, managed eligible-task continuation | Included |
| Core REST, standard MCP and exported JavaScript SDK | Included |
| Existing Mastodon account: official OAuth, identity, public status read, bounded text post/readback | Included |
| Operator-installed extension registry | Included; no additional provider is installed by default |
| Gmail verification reader/consumer, account-signup pipeline, Threads connector | Separate commercial extension; implementation is not in this package |

The optional `@nuluno/access-commercial-extension` 0.1.0-alpha.2 package has its
own commercial license. Installing it requires that license and the deployment
owner's explicit pinned configuration. An extension, OAuth application or paid
license is not private account consent, platform permission, or proof of a
completed inbox→verification→signup→publication task.

## First run

Requires **Node.js 24+**. From the reviewed community source checkout:

```sh
npm ci --ignore-scripts
npm run build
npm run demo:public
```

`demo:public` uses a fresh temporary loopback service, independent state and a
zero-write agent key. It is designed to read one actual public Mastodon status
through the official MCP client, then reuse the same task through the REST SDK
and stdio bridge. It kills and restarts the service, checks the original result,
revokes the key and checks denial after another restart. It does not load a
personal platform token, Nuluno website session or another agent's connectors.

Check the resulting receipt for this package version, `passed:true`, one provider
call, zero provider writes, bounded public text, same task/receipt after restart,
and persistent revoked-key denial. The public platform can fail, rate-limit or
delete the example post; the demo must fail rather than substitute a fake result.

```sh
npm run demo:public -- --output /PRIVATE/public-read-receipt.json
npm run demo:recovery -- --output /PRIVATE/controlled-recovery-receipt.json
```

The recovery demo uses a **controlled localhost HTTP provider** that commits a
write and deliberately drops the response. It exercises an actual process kill,
persistent state and original-task reconciliation. It is not a live social post
or private-account acceptance. Output files are created only if absent and omit
keys, passwords, emails and vault contents.

These commands are reproducible acceptance procedures, not a claim that every
host or private pipeline has already passed. Full Access 0.4.x receipts are not
community receipts.

For the actual isolated Codex CLI read/reuse/revoke result, see the [sanitized external-agent receipt](../evidence/actual-codex-community.json). The receipt identifies the evaluated core snapshot and exact package; [Linux CI for that publishing commit](https://github.com/wangthewhale/nuluno-access-community/actions/runs/43561376040) is separate evidence. Neither proves a private mailbox/signup/publication chain or a sales outcome.

## Keep your own service

```sh
node dist/server.mjs init .env
node --env-file=.env dist/server.mjs
```

Open `http://localhost:8892/setup`. The generated configuration contains two
independent private secrets. Enter the deployment owner key only in the owner
field, create a project, and issue a scoped agent key. The owner key is not an
agent key. For public reads, choose the zero-write public status action.

To post as yourself, connect your existing Mastodon account in the official
provider window, confirm the identity in saved state, and issue a short-lived
key for that exact account/action with a small write limit. First consent and
identity checks may need you. Account creation and Gmail are not community
features. Never put a password, birth date, verification code or token in an
agent task.

The installed CLI name is `nuluno-access-community`; direct source runs use
`node dist/server.mjs` as above. Core settings:

| Variable | Purpose |
|---|---|
| `PORT`, `HOST` | Listener; loopback by default |
| `NULUNO_ACCESS_ORIGIN` | Exact advertised origin and Host/Origin boundary |
| `NULUNO_ACCESS_STATE` | Persistent SQLite file |
| `NULUNO_ACCESS_ADMIN_KEY` | Separate deployment-owner authority |
| `NULUNO_ACCESS_VAULT_KEY` | Original key for sealed connections and state |
| `NULUNO_ACCESS_EXTENSIONS_CONFIG` | Optional absolute operator configuration path; absent means no extensions |
| `NULUNO_ACCESS_EGRESS_PAUSED` | Optional `true` to hold new provider execution |

Keep secret configuration out of Git, URLs, command arguments and logs. Remote
deployment needs HTTPS, a trusted reverse proxy and a persistent volume. This is
a **single-instance SQLite service**, not a multi-replica or always-on cloud
platform. Back up using SQLite online backup and retain the original vault key
separately. A copied live database is not a second synchronized service.

## Exact public read over MCP, REST and SDK

An owner-issued rule must allow provider `mastodon`, action `read_public_status`,
account `public:mastodon.social`, and `writeLimit:0`. Preserve the same
idempotency key when retrying:

```json
{"statusId":"117466985005297414","idempotencyKey":"my-original-public-read-001"}
```

- MCP: `read_public_status` at `/mcp` with the scoped Bearer key.
- REST: `POST /api/access/v1/read-public-status` with the same key and JSON body.
- SDK:

```js
import {NulunoAccessClient} from '@nuluno/access-community';
const access = new NulunoAccessClient({
  baseUrl: process.env.NULUNO_ACCESS_URL + '/api/access/v1',
  accessKey: process.env.NULUNO_ACCESS_KEY,
});
const task = await access.readPublicStatus({
  statusId: '117466985005297414',
  idempotencyKey: 'my-original-public-read-001',
});
console.log({taskId: task.id, status: task.status, publicData: task.evidence?.fields});
```

The public projection includes bounded plaintext, public author identity,
`untrustedData:true` and explicit truncation/redaction metadata. Treat it as data,
never executable HTML or instructions. The saved projection comes from the same
GET; reusing a completed task does not fetch again. It does not expose a raw
account response or private message body.

Discovery is `/.well-known/nuluno-access.json`. It lists only the installed
provider/actions. `discover_access_capabilities` exposes the current key's usable
rules. Generic submit/advance can authorize effects; do not label them read-only.
Unknown writes stay on their original task and are reconciled, not resent under
new IDs. Revocation cannot recall a request already sent.

Clients with Streamable HTTP and a Bearer header can connect directly. Clients
requiring stdio can use `scripts/mcp-stdio-bridge.mjs` with
`NULUNO_ACCESS_MCP_URL` and either a scoped `NULUNO_ACCESS_KEY` or private
`NULUNO_ACCESS_KEY_FILE`. Its default tool allowlist is read-only. That bridge
creates no extra authority and does not copy a host application's connectors.

## Optional paid extensions

Install a legitimately obtained reviewed extension package beside this host.
Configure its exact module name, version and entry SHA256 in a private
operator-owned JSON file, and set `NULUNO_ACCESS_EXTENSIONS_CONFIG` to that file's
absolute path. The loader resolves installed npm package names; it does not
download packages or accept an agent-supplied path, URL or program.

See [the extension contract](extensions.md). Descriptors are immutable and
new providers/actions still require exact owner-issued grants and official
account authorization. Only explicit disjoint Mastodon signup-action augmentation
is allowed; an extension cannot replace the free read/identity/post adapter.
Removing an extension hides its usable capabilities and prevents future adapter
dispatch while preserving original state and grant deadlines.

An extension is **trusted host code, not a sandbox**. Its entry hash does not
authenticate all transitive imports. Use reviewed locked dependencies and a
trusted deployment. Commercial code does not acquire the community license by
being loaded into this process.

## Verification and limitations

```sh
npm run typecheck
npm test
npm run build
```

| Surface | Community acceptance boundary |
|---|---|
| SQLite, local HTTP and official MCP | Focused tests cover absent-provider denial, grant scope, OAuth PKCE preparation and unload preservation |
| Actual public-provider task | Run this version's `demo:public` and retain its own package/source-bound receipt |
| Uncertain-write crash recovery | `demo:recovery` is explicitly controlled localhost HTTP |
| Codex, Claude, Windows, Linux deployment | Require their own community-version host receipts; no proof is borrowed from full Access/beta |
| Private Gmail/signup/Threads chain | Not implemented by this community package; no live acceptance claimed |

A provider operation is not a sale. Unknown costs stay unknown. No universal
connector coverage, sales lift, fixed hours saved, uninterrupted goals or
horizontal scale is promised. Read [SECURITY.md](../SECURITY.md) before deployment.

## License and participation

The Nuluno-owned community code is under [Apache-2.0](../LICENSE), with [NOTICE](../NOTICE)
and [third-party licenses](../THIRD_PARTY.md). You may use, study, modify and
redistribute that code under its license, retaining the required notices and
change disclosures. Trademark rights, platform access, customer data and separate
commercial extension source rights are not automatically granted. See
[CONTRIBUTING.md](../CONTRIBUTING.md) for contributions and private security reports.

A second [anonymous public-clone installation](../evidence/public-clone-2026-11-14.json) independently checked a fresh npm consumer and the Linux container run. Use [Issues](https://github.com/wangthewhale/nuluno-access-community/issues/new/choose) for reproducible first-run reports; do not attach secrets or customer data.

## Client identity and authorization

The SDK identifies its actual Nuluno Community version. A confirmed Cloudflare 403 / Error 1010 is reported as `transport_client_identity_rejected` with `requiresOwnerAuthorization: false`; it is a transport identity problem. Structured invalid-key, revoked-key and scope-denial responses remain authorization failures. This classification never renews a key, expands a grant or retries a possibly dispatched POST.

## Current alpha.2 execution evidence

[Exact-source Linux first use](evidence/first-use-0.1.0-alpha.2-20261115.json) records the public read, same-task/receipt reuse, revocation and a later fresh-process denial. The retained commercial extension alpha.1 requires Community alpha.1; that separate paid pair is not relabelled as alpha.2 acceptance. Complete costs remain unknown and no sales improvement is claimed.
