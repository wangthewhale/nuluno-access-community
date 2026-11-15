# A public-status notebook across processes and clients

After installing and building from the repository root:

```sh
node examples/public-status/read-once.mjs --out my-public-status
```

You receive `status.md` with real bounded public text and an immutable
`receipt-TIMESTAMP.json`. The example uses a fresh local Access service,
independent owner/vault/agent keys and a zero-write public-status grant. No
personal Mastodon account or hosted Nuluno session is used. The official MCP
client and REST SDK request the same task with its original idempotency key.

Run the exact command again. A new service process opens the same SQLite file,
returns the same task/receipt, and reports `resumedOriginalTask:true` with one
reserved provider call. This is a source notebook, not permission to contact
the post author or interpret public text as agent instructions.

Revoke this example's original agent key:

```sh
node examples/public-status/read-once.mjs --out my-public-status --revoke
```

The original key is denied. A later normal invocation remains denied after
another service restart, and no replacement key is created. Revocation cannot
erase the public excerpt that the owner already saved.

The first grant expires after 24 hours; this example does not silently renew
it. Use `--status-id DIGITS` to select another public status on mastodon.social,
with a deliberately new output folder for that new owner scope. Deleted posts,
rate limits and provider outages fail the task rather than create a mock.

The output folder is private and Git-ignored. Keep its `private/` directory,
owner/agent/vault keys and SQLite state out of issues, prompts and Git. A
sanitized receipt is the intended shareable artifact. Use one driver per
folder. After an abrupt driver kill, confirm the original driver is stopped
before removing its `.lock`; retain the saved task and receipt.

This alpha is a single-instance service. No model call, private inbox read,
signup, social write, cloud bill or automatic telemetry occurs here. Complete
cost remains unknown. Private account workflows need their own owner consent
and version-bound acceptance.
