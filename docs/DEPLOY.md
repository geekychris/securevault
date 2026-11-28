# Deploying SecureVault in the lab

SecureVault is a cloud-stack app: `cloudstack.app.yaml` at the repo root
describes how to build, run, check and register it, and `deploy/cloudstack/`
holds plain Kubernetes manifests for a **single node** with a persistent
volume.

| | |
|---|---|
| Namespace | `securevault` |
| Workload | Deployment `securevault`, 1 replica, `strategy: Recreate` (the file backend is single-writer) |
| Storage | PVC `securevault-data`, 1Gi, mounted at `/vault/data` (secrets, policies, seal data, token store, audit log) |
| Config | ConfigMap `securevault-server` → `/vault/config/config.yaml` |
| API / UI | Service `securevault`, port 8200, NodePort 30950; UI at `/ui/` |
| Route | `securevault.hitorro.com`, `internal` (LAN only); TLS is terminated at the proxy |
| Resources | requests 50m CPU / 64Mi, limits 500m / 256Mi |
| Pod security | non-root (uid 1000), read-only root filesystem, no capabilities, no service-account token |

## Install

From a cloud-stack checkout (builds on the host, applies the manifests, checks
health, then opens the pull request that registers the app):

```sh
deploy/app/install.sh geekychris/securevault spark --check
deploy/app/install.sh geekychris/securevault spark --plan    # install, show the inventory diff
deploy/app/install.sh geekychris/securevault spark           # install from main and register
```

When `spark.local` doesn't resolve, prefix
`SSH_OPTS="-o HostName=192.168.1.177 -o HostKeyAlias=spark.local"`.
It needs no saaspack storage, so any lab host works; spark is the default.

Standalone, against whatever cluster your `kubectl` points at (Rancher
Desktop, a lab host):

```sh
scripts/install-k8s.sh --check
scripts/install-k8s.sh
```

`scripts/install-k8s.sh` is a copy of cloud-stack's `deploy/app/app-install.sh`.
Re-copy it from there when cloud-stack changes it; don't edit it here.

## First start: initialize

A new install is **uninitialized**. Initialize it once, from a machine you
trust, and store what comes back:

```sh
scripts/init-vault.sh -a http://spark.hitorro.com:30950      # 5 shares, threshold 3 (config)
```

It writes the five unseal key shares and the root token to
`~/securevault-init.json` (mode 600) and never prints them, so they don't end
up in terminal scrollback, logs or chat. It refuses to run if that file
already holds a result or the vault is already initialized, so a second run
can't overwrite the only copy. Don't initialize with a bare `curl` to the
terminal. The shares and token are given out **once** and can't be recovered (the server keeps only a hash of the
master key). Give the shares to different holders or store them separately;
keep the root token for break-glass use, create policy-scoped tokens for
day-to-day work, then `POST /v1/auth/token/revoke-self` with the root token. Delete the file
once the shares are with their holders.

If the output was lost before anything was stored, the only way back is to
delete the data volume and initialize again: `kubectl -n securevault scale
deploy/securevault --replicas=0`, `kubectl -n securevault delete pvc
securevault-data`, then re-run the install.

## Every restart: unseal

The vault starts **sealed** after every pod restart, upgrade or node reboot.
Until three shares are submitted it serves nothing but status:

```sh
curl -s -X POST http://spark.hitorro.com:30950/v1/sys/unseal -d '{"key":"<share>"}'   # three times, three different shares
curl -s http://spark.hitorro.com:30950/v1/sys/seal-status
```

There is no auto-unseal: that's deliberate for a lab without an HSM or KMS.

## Health

`/v1/sys/health` follows Vault: 200 initialized and unsealed, 501
uninitialized, 503 sealed, 429 on a standby, with query parameters to remap
those codes.

- **Kubernetes probes** use `?standbyok=true&uninitcode=204&sealedcode=204`,
  so a sealed pod stays Ready and reachable for unsealing.
- **cloud-stack** probes `?uninitcode=204&sealedcode=423`. Installs and
  upgrades (which restart the vault sealed) pass the installer's check, and
  the Infra tab shows HTTP 423 while the vault is sealed.
- cloud-stack's probe counts anything below 500 as up, so a **sealed vault
  does not raise `service_down`**. Check the Infra tab's status code after a
  restart.

## Backups

Everything is in the PVC, encrypted with the data key, which is wrapped by
the master key (the shares). A copy of `/vault/data` restores the vault
together with the same unseal shares:

```sh
kubectl -n securevault exec deploy/securevault -- tar czf - -C /vault data > securevault-$(date +%F).tgz
```

The audit log (`/vault/data/audit/audit.log`) is not encrypted. It records
paths, accessors and outcomes, never secret values or tokens.

## Clients in the cluster

In-cluster clients can use `http://securevault.securevault.svc.cluster.local:8200`
(plaintext inside the cluster) and send `X-Vault-Token`. From the LAN use
`https://securevault.hitorro.com`.

## Unseal lockout

`unseal_lockout` locks a source address out after 10 failed unseal attempts
in 15 minutes, for 5 minutes. Behind the proxy and kube-proxy most callers
share a source address, so a lockout blocks everyone for those 5 minutes. A
wrong or repeated share counts as a failure.

## Not configured

`configs/production.yaml` documents more settings than the server reads. The
server reads `server`, `storage`, `auth.token_ttl`, `auth.token_max_ttl`,
`seal`, `rate_limit`, `unseal_lockout`, `audit` and `replication`. The rest
(`logging`, CORS, IP allow-lists, backups, cipher suites and so on) is
ignored.
