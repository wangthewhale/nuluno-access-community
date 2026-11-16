# Account Hub host contract

The Hub imports public core modules from this repository. It never imports neighboring private cloud source. The installed CLI resolves operator-selected extensions with `loadAccessExtensions`: exact npm module, version, entry hash and manifest checks remain. A commercial extension must declare this candidate's **exact** community peer version; alpha.2 packs are rejected before loading. No provider/module/URL can be installed by an agent payload.

The extension's documented host secrets are `NULUNO_ACCESS_COMMERCIAL_GOOGLE_CLIENT_ID` and `NULUNO_ACCESS_COMMERCIAL_GOOGLE_CLIENT_SECRET`. They are only checked as configured flags by the Hub. The installed extension owns OAuth itself; the public addon ships no Gmail connector. Its official callback remains `ORIGIN/oauth/google/callback`. Google application verification, provider policies, CAPTCHA and first consent are not bypassed.

Owner activation uses `/account-hub/activate#pair=…`. The server stores only a hash of the one-use five-minute capability, installation ID, generation and expiry. Pairing POST requires exact Origin, a bounded pre-session and its CSRF. Consuming the capability and creating the owner session happen in one SQLite transaction. Existing cookie plus missing/old proof can use a fresh activation link without clearing cookies.

The successful pairing POST returns an owner proof once. The browser stores only that proof in origin-scoped sessionStorage, or localStorage when device remembering is selected. Every owner API, including state reads, requires the HttpOnly cookie **and** `X-Hub-Owner-Proof`. The database stores a hash of the proof. GET and HTML never return it. OAuth state, pairing material, platform credentials and agent keys never use browser storage. The activation fragment is cleared synchronously; owner pages are static shells independent of cookies. Logout deletes the session and browser proof.

This protects against authority gained from collecting another loopback port's cookie alone. It is not protection against same-origin XSS, malicious trusted extensions, a compromised browser or a process with the owner's full terminal/keystore access.

The local `hub_agent_tokens` table seals each public-read key separately from managed runners. `POST /hub-api/agents` binds the original requestKey, grant and sealed key atomically. Retries retain its original deadline. Only an explicit owner/CSRF connection download returns that restricted key. Revocation retires its sealed copy while preserving the original grant, tasks and receipts. The Hub never enables private-write presets.

## Installation key source

The Apache key-source module and dedicated Swift helper source are included under `src/account-hub/keys`. The master never falls back to an installation-state file. On macOS the helper accesses only the current non-root user's default file keychain, under this installation's UUID. It does not enumerate, delete, update ACLs, use iCloud/DPK or switch to another key store. OS unlock/consent and the helper's stable signing/path matter during installation and upgrades.

Git source includes Swift and the build script, not a machine-specific Mach-O or manifest. The CLI compiles a missing helper before using the macOS source; missing Swift produces a clear Command Line Tools error. A locally generated manifest pins that compiled binary. Linux and explicit operator-env do not compile or invoke Swift. Source metadata and binding files are 0600; the state directory is 0700. The adapter rejects missing/changed original metadata, master or binding instead of generating a replacement identity.

For an embedded host, pass a server-only keySource to `createAccountHub`. Return the getters from `loadInstallationKeys`; do not spread or serialize secret material. Source selection, external master injection, helper path and extension configuration are host startup inputs, never HTTP/MCP parameters.

This is single-owner loopback operation. There is no KMS, multi-tenant hosted login, authenticated cloud user directory or financial spending authority. Do not expose it publicly by changing only the bind address.
