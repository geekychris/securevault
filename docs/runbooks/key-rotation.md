# Runbook: Shamir unseal-share rotation

## When to run this

- A share-holder leaves the team, is suspected of being compromised, or
  simply shouldn't have access to the current shares anymore.
- You want to change the number of shares or the unseal threshold (e.g.
  moving from 5 shares/3 threshold to 7 shares/4 threshold).
- Periodic/scheduled rotation as part of your security policy.

This procedure **re-keys** the vault: it generates a brand-new master key,
re-wraps the existing (unchanged) data-encryption key under it, and splits
the new master key into a new set of shares. It does **not** touch any
stored secret data — there is no bulk re-encryption and no downtime beyond
the single API call.

## Pre-conditions

- The vault must be **unsealed** (`GET /v1/sys/seal-status` → `"sealed": false`).
- You need a token with `update` capability on the `sys/rotate-shares` path.
  Root tokens have this by default.

## Procedure

1. **Unseal the vault** if it isn't already:

   ```bash
   curl -X POST http://127.0.0.1:8200/v1/sys/unseal -d '{"key": "<share>"}'
   # repeat until "sealed": false
   ```

2. **Rotate the shares.** Decide on the new share count and threshold, then call:

   ```bash
   curl -X POST http://127.0.0.1:8200/v1/sys/rotate-shares \
     -H "X-Vault-Token: $VAULT_TOKEN" \
     -d '{"new_secret_shares": 5, "new_secret_threshold": 3}'
   ```

   The response contains the new share set:

   ```json
   {"keys": ["<share-1>", "<share-2>", "...", "<share-5>"], "threshold": 3, "num_shares": 5}
   ```

   Or via the Go client:

   ```go
   resp, err := client.RotateShares(ctx, 5, 3)
   ```

3. **Distribute the new shares** to the appropriate holders immediately,
   using your normal out-of-band secret-distribution process (e.g. one
   share per holder, over separate channels). The response is the only time
   the new shares are ever returned — they are not retrievable afterward.

4. **Destroy the old shares.** Every share-holder who had an old share
   should delete it. This step matters less for security (the old shares
   stop working the instant step 2 completes — see "Why old shares stop
   working" below) but it avoids confusion about which shares are current.

5. **Verify the new shares work.** This is the most important step — do not
   skip it. Seal the vault and unseal it again using only the new shares:

   ```bash
   curl -X POST http://127.0.0.1:8200/v1/sys/seal -H "X-Vault-Token: $VAULT_TOKEN"
   curl -X POST http://127.0.0.1:8200/v1/sys/unseal -d '{"key": "<new-share-1>"}'
   curl -X POST http://127.0.0.1:8200/v1/sys/unseal -d '{"key": "<new-share-2>"}'
   curl -X POST http://127.0.0.1:8200/v1/sys/unseal -d '{"key": "<new-share-3>"}'
   # → {"sealed": false}
   ```

   If the vault was sealed deliberately as part of this check, confirm
   application traffic resumes normally once unsealed.

## Why old shares stop working

Rotation generates a completely new master key — it does not just re-split
the existing one (re-splitting the same key can never invalidate old shares,
since they'd all still be points on the same secret-sharing polynomial).
Because of that:

- Old shares still mathematically reconstruct the **old** master key, but
  `POST /v1/sys/unseal` rejects the result because it no longer matches the
  master-key hash stored in the rotated seal data.
- Even if that check were bypassed, the old master key cannot decrypt the
  re-wrapped data-encryption key (it's sealed with AES-256-GCM, so decrypting
  with the wrong key fails authentication) — a second, independent reason
  the old shares can no longer unseal the vault.

## Rollback

There is no "undo" for a rotation — once step 2 completes, the old shares
are permanently invalidated. If the rotation call fails outright (non-2xx
response), the vault's existing shares and threshold are untouched; the
seal data is only replaced after the new shares have been successfully
generated, so a failed rotation attempt is always safe to retry.

If you rotate successfully but then lose the new shares before distributing
them, there is no way to recover: generate a fresh rotation immediately
while the vault is still unsealed, since the master key before that point
is unrecoverable once sealed without enough of either share set.

## Operational notes

- Rotation is a single authenticated API call today (unsealed vault +
  privileged token), the same authorization bar as `sys/seal`. It does not
  require presenting a fresh quorum of the *current* shares as proof of
  intent. If your threat model requires that stronger guarantee (e.g. a
  "propose rotation, collect quorum approval, then commit" workflow similar
  to HashiCorp Vault's rekey operation), treat that as a future hardening
  item — it is not implemented here.
- Rotation is a per-node operation, consistent with how `init`/`seal`/`unseal`
  already work in this codebase. In a replicated deployment, run this
  against each node that maintains its own seal state.
- Audit log entries are recorded as `sys.rotate_shares` events (success and
  failure) — check `GET /v1/audit/events` after a rotation to confirm it was
  logged as expected.
