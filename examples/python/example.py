#!/usr/bin/env python3
"""
Vaultrix Python Client Example

Usage:
    python example.py <vault-address> [token]

Example:
    python example.py http://127.0.0.1:8200
    python example.py http://127.0.0.1:8200 s.my-root-token
"""

import sys
import json
import requests


class SimpleVaultClient:
    """Simple vault client for the example (no dependency on the full client library)."""

    def __init__(self, address, token=""):
        self.address = address.rstrip("/")
        self.token = token

    def _headers(self):
        h = {"Content-Type": "application/json"}
        if self.token:
            h["X-Vault-Token"] = self.token
        return h

    def _url(self, path):
        return f"{self.address}{path}"

    def get_seal_status(self):
        r = requests.get(self._url("/v1/sys/seal-status"), headers=self._headers())
        r.raise_for_status()
        return r.json()

    def initialize(self, secret_shares=3, secret_threshold=2):
        r = requests.post(
            self._url("/v1/sys/init"),
            headers=self._headers(),
            json={"secret_shares": secret_shares, "secret_threshold": secret_threshold},
        )
        r.raise_for_status()
        return r.json()

    def unseal(self, key):
        r = requests.post(
            self._url("/v1/sys/unseal"),
            headers=self._headers(),
            json={"key": key},
        )
        r.raise_for_status()
        return r.json()

    def write_secret(self, path, data):
        r = requests.post(
            self._url(f"/v1/secret/{path}"),
            headers=self._headers(),
            json={"data": data},
        )
        r.raise_for_status()

    def read_secret(self, path):
        r = requests.get(self._url(f"/v1/secret/{path}"), headers=self._headers())
        r.raise_for_status()
        return r.json()

    def delete_secret(self, path, destroy=False):
        url = self._url(f"/v1/secret/{path}")
        if destroy:
            url += "?destroy=true"
        r = requests.delete(url, headers=self._headers())
        r.raise_for_status()

    def list_secrets(self, path):
        r = requests.get(self._url(f"/v1/secret/list/{path}"), headers=self._headers())
        r.raise_for_status()
        return r.json().get("keys", [])

    def create_token(self, policy_ids, ttl="1h"):
        r = requests.post(
            self._url("/v1/auth/token/create"),
            headers=self._headers(),
            json={"policy_ids": policy_ids, "ttl": ttl},
        )
        r.raise_for_status()
        return r.json()["auth"]["client_token"]

    def create_policy(self, name, description, rules):
        r = requests.post(
            self._url("/v1/policies"),
            headers=self._headers(),
            json={
                "policy": {
                    "name": name,
                    "description": description,
                    "rules": rules,
                }
            },
        )
        r.raise_for_status()

    def delete_policy(self, name):
        r = requests.delete(self._url(f"/v1/policies/{name}"), headers=self._headers())
        r.raise_for_status()

    def health(self):
        r = requests.get(self._url("/v1/health"), headers=self._headers())
        return r.json()


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    vault_addr = sys.argv[1]
    token = sys.argv[2] if len(sys.argv) >= 3 else ""

    client = SimpleVaultClient(vault_addr, token)

    # --- Initialize and Unseal ---
    if not token:
        print("=== Checking Vault Status ===")
        status = client.get_seal_status()
        print(f"Initialized: {status['initialized']}, Sealed: {status['sealed']}")

        if not status["initialized"]:
            print("Initializing vault...")
            init_resp = client.initialize(secret_shares=3, secret_threshold=2)

            print(f"Root Token: {init_resp['root_token']}")
            print("Unseal Keys:")
            for i, key in enumerate(init_resp["keys"]):
                print(f"  Key {i + 1}: {key}")
            print("\n*** SAVE THESE KEYS SECURELY ***\n")

            token = init_resp["root_token"]
            client.token = token

            # Unseal with threshold keys
            for i in range(2):
                seal_status = client.unseal(init_resp["keys"][i])
                print(f"Unseal progress: {seal_status['progress']}/{seal_status['threshold']}")
                if not seal_status["sealed"]:
                    print("Vault is unsealed!")

        elif status["sealed"]:
            print("Vault is sealed. Provide unseal keys.")
            sys.exit(1)

    # --- Policy Management ---
    print("\n=== Policy Management ===")
    try:
        client.create_policy(
            name="app-reader",
            description="Read-only access to app secrets",
            rules=[{"path": "app/**", "capabilities": ["read", "list"]}],
        )
        print("Created 'app-reader' policy")
    except Exception as e:
        print(f"Create policy: {e}")

    # --- Secret Operations ---
    print("\n=== Secret Operations ===")

    # Write secrets
    client.write_secret("app/database/config", {
        "host": "db.internal.example.com",
        "port": 5432,
        "username": "app_user",
        "password": "super-secret-password",
    })
    print("Written secret: app/database/config")

    client.write_secret("app/api/keys", {
        "api_key": "ak_live_xxxxxxxxxxxx",
        "api_secret": "sk_live_xxxxxxxxxxxx",
    })
    print("Written secret: app/api/keys")

    # Read a secret
    secret = client.read_secret("app/database/config")
    data = secret["data"]
    meta = secret["metadata"]
    print(f"Read: host={data['host']}, user={data['username']} (v{meta['version']})")

    # Update (creates version 2)
    client.write_secret("app/database/config", {
        "host": "db.internal.example.com",
        "port": 5432,
        "username": "app_user",
        "password": "rotated-password-2024",
    })
    print("Updated secret (new version)")

    # List secrets
    keys = client.list_secrets("app")
    print(f"Secrets under app/: {keys}")

    # --- Token Management ---
    print("\n=== Token Management ===")

    restricted_token = client.create_token(["app-reader"], ttl="2h")
    print(f"Created restricted token: {restricted_token[:10]}...")

    # Use restricted token
    restricted = SimpleVaultClient(vault_addr, restricted_token)

    # Read should work
    secret = restricted.read_secret("app/database/config")
    print(f"Restricted read: host={secret['data']['host']}")

    # Write should fail
    try:
        restricted.write_secret("app/database/config", {"hacked": True})
        print("ERROR: Write should have been denied!")
    except requests.HTTPError as e:
        print(f"Restricted write correctly denied: {e.response.status_code}")

    # --- Cleanup ---
    print("\n=== Cleanup ===")
    client.delete_secret("app/database/config", destroy=True)
    print("Destroyed app/database/config")
    client.delete_secret("app/api/keys", destroy=True)
    print("Destroyed app/api/keys")
    client.delete_policy("app-reader")
    print("Deleted app-reader policy")

    # Health check
    health = client.health()
    print(f"\nVault health: {health['status']}")
    print("\n=== Example Complete ===")


if __name__ == "__main__":
    main()
