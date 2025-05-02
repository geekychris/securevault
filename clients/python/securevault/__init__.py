"""
SecureVault Python Client

A Python client library for interacting with the SecureVault secrets management system.
"""

__version__ = "0.1.0"

from .client import SecureVaultClient, AsyncSecureVaultClient
from .exceptions import (
    SecureVaultError,
    SecureVaultConnectionError,
    SecureVaultAuthenticationError,
    SecureVaultForbiddenError,
    SecureVaultNotFoundError,
)
from .models import Secret, Policy, SecretMetadata, PolicyRule, ReadOptions, DeleteOptions, WriteOptions

__all__ = [
    "SecureVaultClient",
    "AsyncSecureVaultClient",
    "SecureVaultError",
    "SecureVaultConnectionError",
    "SecureVaultAuthenticationError",
    "SecureVaultForbiddenError",
    "SecureVaultNotFoundError",
    "Secret",
    "Policy",
    "SecretMetadata",
    "PolicyRule",
    "ReadOptions",
    "DeleteOptions",
    "WriteOptions",
]

