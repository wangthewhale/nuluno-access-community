# Nuluno Access Community — Account Hub candidate

Connect accounts once. Give an AI agent a narrow permission. Keep the task and receipt through a restart. Revoke that permission when you are done.

**Candidate `0.1.0-alpha.3-hub.1`.** This source addon builds on the Apache-2.0 community core. It does not replace the published, immutable alpha.2 release. It is a local, single-owner installation, not a hosted membership system or a promise of autonomous sales.

## Try from this source checkout

Requires Node 24 or newer. There is no dependency on Nuluno.com, another source directory, or another agent's platform credentials.

```sh
npm ci
npm run hub -- --state "$HOME/.local/share/nuluno/access-hub"
```

On macOS, the installer uses the dedicated **macOS file-keychain** source. If the helper has not been built, the CLI builds the included Swift source and its local SHA-256 manifest before requesting a key. Apple Command Line Tools are required. A locked keychain or an OS consent request can require you. There is no plaintext master-key fallback.

The CLI shows a private, five-minute, one-use activation link in your terminal. Open it yourself. The link is removed from the address bar before a request is made. After activation, the browser remembers its own access proof; the service receives an HttpOnly session cookie. Choose “在這台裝置記住目前專案” to retain access across browser restarts. This is local device access, not a cloud login.

If you lose browser access, run the same CLI with `pair` and the same state directory. Its dedicated `/account-hub/activate` page works even if an older cookie remains. You do not need to clear cookies or reconnect a platform.

```sh
nuluno-access-hub pair --state "$HOME/.local/share/nuluno/access-hub"
```

For a headless/operator installation, inject a persistent, private `NULUNO_ACCESS_MASTER_KEY` from your secret manager: exactly 32 random bytes in canonical base64url form. Explicitly select `--key-source operator-env` and use `--pairing-file /private/new-owner.pairing-link`. That file is created once with mode 0600; open its link privately and remove it after use. Do not put the master or activation link in chat, Git, logs, or a shared shell history. Losing or changing the original master fails closed; it never silently resets the installation.

## Connect an AI agent

1. Activate your device and open the Account Hub.
2. Press **建立公共只讀連接**. The preset permits only public Mastodon status reads for one hour, at most 25 tasks, with zero writes. It grants no inbox, login, publication, payment, or owner access.
3. Press **下載 MCP 連接資料**. This explicitly downloads the agent's restricted key, endpoint and Authorization header. It is not a platform password or a universal configuration file for every agent.
4. Use those values in a client that supports MCP Streamable HTTP. The official MCP SDK accepts this connection data:

```js
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
const client = new Client({ name: 'my-agent', version: '1' });
await client.connect(new StreamableHTTPClientTransport(new URL(connection.url), {
  requestInit: { headers: connection.headers }
}));
// Call read_public_status with a stable idempotencyKey. Reuse it on retry.
```

5. Press **撤銷連接** to deny that same key in HTTP and MCP. Original tasks and receipts remain. Downloads contain a short-lived credential: keep them private. Other hosts, including Codex and Claude, have their own connection configuration formats; adapt the endpoint and header to the host's documented format.

## What is included

- The working community broker, scoped keys, encrypted credential vault, durable SQLite tasks, reconciliation, receipts, revocation, REST/MCP and SDK.
- Existing-account Mastodon OAuth and the free Mastodon adapter. A real platform authorization still needs its official first consent. This candidate does not claim a live private-account OAuth acceptance.
- A Traditional Chinese Account Hub with explicit owner activation, remembered connections, device preference, cancellation and agent connection controls.
- Each physical platform request is admitted separately. Slow provider I/O does not hold the SQLite transaction, so revocation can commit while a request is in flight. Late safe receipts stay on the original revoked task; no follow-up request is admitted after revocation.
- Disconnecting an account atomically retires its dependent keys and managed work. Public-only and unrelated-account keys remain separate; reconnecting does not revive the old permission or reset its quota.
- Atomic per-project/provider OAuth admission. Cancellation retires pending/exchanging state; a late start or callback cannot restore the canceled connection.
- Cookie plus an origin-scoped browser proof for owner APIs. A copied localhost cookie alone cannot read state or obtain CSRF. These are access proofs, **not two-factor authentication**.

## What is deliberately unavailable

**Gmail is disabled in free core.** Google appears as available only when an operator installs a compatible commercial extension through the original pinned registry and supplies that extension's own Google client configuration. No private Google connector code is shipped here. The existing alpha.2 commercial extension has an exact alpha.2 peer dependency and is **not accepted as compatible with this candidate**. No `--force` or `--legacy-peer-deps` workaround is supported. A compatible extension release and its real private flow require separate acceptance.

Payment, automatic account signup, private mail verification consumption, social-write onboarding and cloud membership are not enabled by the Hub. Installing it does not prove sales, savings or completed private tasks. See [extensions](docs/account-hub.md) and [security](SECURITY.md).

## Build, tests and reproducible consumer check

```sh
npm run typecheck
npm test
npm run build
npm pack
```

Install the resulting candidate tarball into a clean project. `scripts/accept-portable-hub.mjs --installation /absolute/consumer --output /private/new-receipt.json` boots the installed CLI with a disposable operator master, activates through owner APIs, obtains the agent key through the UI's API, makes **one real public GET** through the official MCP SDK, reuses its task/receipt after restart, and verifies revocation after restart. A provider outage fails the check; there is no mock replacement. This does not test Keychain, private OAuth or business outcomes.

The original `nuluno-access-community` CLI and `dist/server.mjs` entry remain available. `createAccessApp` is also exported by `./app` as a pure factory so bundling the Hub cannot accidentally start the old CLI.

This remains a candidate. macOS helper consent/signing upgrades, Linux CI and actual browser acceptance must be reported for their exact tested environment; an operator-env consumer pass is not proof that every Mac or hosted deployment is ready.
