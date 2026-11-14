<!-- SPDX-License-Identifier: Apache-2.0 -->
# Operator-installed provider extensions

Access Community runs a real core and built-in Mastodon provider. An uninstalled
extension contributes no provider or action. Loading an extension is a deployment
owner decision, not an agent tool, task payload, remote instruction or inferred
permission. Installation alone does not connect a private account or expand a key.

The host loader accepts an operator-controlled configuration array. Each entry
has exactly four fields:

```json
[
  {
    "id": "commercial",
    "module": "@nuluno/access-commercial-extension",
    "version": "0.1.0-alpha.1",
    "entrySha256": "REPLACE_WITH_THE_REVIEWED_ENTRY_SHA256"
  }
]
```

The example hash is intentionally invalid until the operator supplies the exact
64 lowercase hexadecimal SHA256 of the reviewed installed entry. It is not a
usable release declaration. The named package must already be installed and
accessible from the configuration file's absolute location. No package is fetched
or installed by the loader. Module strings are npm package names only: no paths,
URLs, subpath imports, code snippets, wildcard ranges or `eval`.

```ts
import {loadAccessExtensions} from '../src/extensions/registry';
const extensions = await loadAccessExtensions(operatorConfig, {
  resolveFrom: '/PRIVATE/DEPLOYMENT/extensions.json',
});
```

For every configured package, the loader resolves the real entry, verifies its
owning package name and exact version, and checks its SHA256 before importing any
entry in the configured set. The package exports this exact manifest:

```ts
export const accessExtension = {
  id: 'commercial',
  version: '0.1.0-alpha.1',
  providers: [
    {provider: 'gmail', actions: ['verify_email'], readOnlyActions: []},
  ],
  install(context) {
    // Return the host integration using the documented trusted context.
    // This function is invoked explicitly by the host, not by task payloads.
  },
};
```

The manifest ID/version must match the operator's entry. Provider/action lists are
strict and become immutable descriptor copies. Read-only actions must be an
explicit subset of that provider's installed actions. Built-in `mastodon` cannot
be replaced. One extension can explicitly add only its disjoint `connect` and
`create_account` actions using `augment:true`; these account-changing actions
cannot be marked read-only. It cannot override `read_public_status`,
`verify_identity`, `publish_text` or any additional host-declared built-in action.
Normal same-name providers, multiple extension owners of one provider, duplicate
actions and augmentation of a non-built-in provider are rejected. The host routes
an augmented provider by the exact installed action; it never replaces the free
Mastodon adapter.

```ts
{provider: 'mastodon', actions: ['connect', 'create_account'],
 readOnlyActions: [], augment: true}
```

The host can pass `builtinActions` to the loader to reserve its additional native
actions. The three mandatory Mastodon actions remain reserved even if a caller
passes an empty list. The default installed set remains empty when no extension
is configured.

The host must validate an installed adapter's provider/action contract before
advertising it, then continue using the same scoped broker, account rules, grant
expiry, task identities, external-step reservations, unknown-write reconciliation
and revocation. A plugin manifest is not proof of private-account consent, native
readback or full Gmail→verification→signup→publication acceptance.

## Trust and packaging boundary

**An extension is trusted host code, not a sandbox.** Its JavaScript executes with
the service process's privileges. A malicious operator-installed module can make
its own network/filesystem calls; a scoped broker is not isolation from code the
deployment owner chose to run. Review the package, its configuration and its
dependencies before installation. An agent must never choose or rewrite this
configuration, its entry hash or its resolution root.

The entry hash authenticates the installed entry bytes; it does not cover all
transitive imports or the full dependency tree. Use a reviewed locked dependency
graph, package integrity/provenance and a trusted immutable deployment image.
Restart to change the installed set; do not treat this port as agent-driven hot
reload or remote plugin discovery. Keep credentials in private host configuration
and the vault, not extension metadata or task payloads.

Community and commercial extension packages can have different licenses.
Installing an extension does not relicense it or transfer platform/account rights.
Keep each package's license and third-party notices with its distribution.
