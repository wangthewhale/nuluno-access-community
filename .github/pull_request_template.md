## Problem and resulting behavior

Describe the concrete trigger and what changes for the user or agent.

## Validation and limits

Name the exact package, client and checks. Separate controlled-localhost tests,
real public-provider execution and any private-account evidence. Preserve failures.

## Trust boundaries

- [ ] No keys, tokens, private account/customer data, databases or restricted extension code are included.
- [ ] Tenant/account/action scope, expiry, limits, original tasks and receipts remain protected.
- [ ] Unknown writes require original-operation readback; no blind POST retry or grant renewal is introduced.
- [ ] Revocation is checked before future external steps and is not described as recalling an already-sent request.
- [ ] New adapters declare consent, trusted-code boundaries, source rights and evidence requirements.
- [ ] License, version, publishing or production changes are explicit parts of the review, if any.
