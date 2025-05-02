"""
SecureVault client implementation.
"""

import json
import logging
import asyncio
from typing import Dict, List, Any, Optional, Union, TypeVar, Generic
import aiohttp
import requests
from dataclasses import asdict
import time

from .models import Secret, Policy, SecretMetadata, PolicyRule, ReadOptions, DeleteOptions, WriteOptions
from .exceptions import (
    SecureVaultError,
    SecureVaultConnectionError,
    SecureVaultAuthenticationError,
    SecureVaultForbiddenError,
    SecureVaultNotFoundError,
    SecureVaultBadRequestError,
    SecureVaultServerError,
)

T = TypeVar('T')

logger = logging.getLogger(__name__)


def _build_url(base_url: str, path: str) -> str:
    """Build a URL by joining the base URL and path."""
    if not base_url.endswith("/"):
        base_url += "/"
    if path.startswith("/"):
        path = path[1:]
    return f"{base_url}{path}"


def _handle_response_error(status_code: int, response_text: str) -> None:
    """Handle error responses from the API."""
    error_msg = f"Status code: {status_code}"
    
    try:
        error_data = json.loads(response_text)
        if isinstance(error_data, dict) and "error" in error_data:
            error_msg = error_data["error"]
    except json.JSONDecodeError:
        if response_text:
            error_msg = response_text
    
    if status_code == 400:
        raise SecureVaultBadRequestError(error_msg)
    elif status_code == 401:
        raise SecureVaultAuthenticationError(error_msg)
    elif status_code == 403:
        raise SecureVaultForbiddenError(error_msg)
    elif status_code == 404:
        raise SecureVaultNotFoundError(error_msg)
    elif status_code >= 500:
        raise SecureVaultServerError(error_msg)
    else:
        raise SecureVaultError(f"Unexpected error: {error_msg}", status_code)


class SecureVaultClient:
    """
    Synchronous client for interacting with the SecureVault API.
    
    Args:
        url: The base URL of the SecureVault server
        token: Authentication token
        timeout: Request timeout in seconds
        max_retries: Maximum number of retry attempts for failed requests
        retry_delay: Delay between retries in seconds
    """
    
    def __init__(
        self,
        url: str,
        token: str,
        timeout: int = 10,
        max_retries: int = 3,
        retry_delay: float = 1.0,
    ):
        self.url = url.rstrip("/")
        self.token = token
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.session = requests.Session()
        self.session.headers.update({
            "X-Vault-Token": token,
            "Content-Type": "application/json",
        })
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
    
    def close(self):
        """Close the client session."""
        self.session.close()
    
    def _request(
        self,
        method: str,
        path: str,
        data: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> Any:
        """Make a request to the SecureVault API with retry logic."""
        url = _build_url(self.url, path)
        retries = 0
        last_error = None
        
        while retries <= self.max_retries:
            try:
                if data is not None:
                    response = self.session.request(
                        method=method,
                        url=url,
                        json=data,
                        params=params,
                        timeout=self.timeout,
                    )
                else:
                    response = self.session.request(
                        method=method,
                        url=url,
                        params=params,
                        timeout=self.timeout,
                    )
                
                if 200 <= response.status_code < 300:
                    if response.status_code == 204 or not response.text:
                        return None
                    return response.json()
                else:
                    _handle_response_error(response.status_code, response.text)
                    
            except requests.exceptions.RequestException as e:
                last_error = e
                retries += 1
                if retries <= self.max_retries:
                    time.sleep(self.retry_delay)
                else:
                    raise SecureVaultConnectionError(f"Connection error after {self.max_retries} retries: {e}")
        
        raise SecureVaultConnectionError(f"Connection error: {last_error}")
    
    def write_secret(
        self,
        path: str,
        data: Dict[str, Any],
        options: Optional[WriteOptions] = None,
    ) -> None:
        """
        Write a secret to the specified path.
        
        Args:
            path: Path where the secret will be stored
            data: Secret data to store
            options: Additional options for writing the secret
        
        Raises:
            SecureVaultError: If the operation fails
        """
        payload = {"data": data}
        
        if options and options.metadata:
            payload["metadata"] = options.metadata
        
        self._request("POST", f"v1/secret/{path}", data=payload)
    
    def read_secret(
        self,
        path: str,
        options: Optional[ReadOptions] = None,
    ) -> Secret:
        """
        Read a secret from the specified path.
        
        Args:
            path: Path to the secret
            options: Options for reading the secret, including version
        
        Returns:
            Secret object containing data and metadata
        
        Raises:
            SecureVaultNotFoundError: If the secret is not found
            SecureVaultError: If the operation fails
        """
        if options and options.version > 0:
            response = self._request("GET", f"v1/secret/versions/{options.version}/{path}")
        else:
            response = self._request("GET", f"v1/secret/{path}")
        
        return Secret(
            data=response.get("data", {}),
            metadata=response.get("metadata", {})
        )
    
    def delete_secret(
        self,
        path: str,
        options: Optional[DeleteOptions] = None,
    ) -> None:
        """
        Delete a secret from the specified path.
        
        Args:
            path: Path to the secret
            options: Options for deletion, including versions and destroy flag
        
        Raises:
            SecureVaultNotFoundError: If the secret is not found
            SecureVaultError: If the operation fails
        """
        params = {}
        
        if options:
            if options.destroy:
                params["destroy"] = "true"
            
            if options.versions:
                params["versions"] = ",".join(map(str, options.versions))
        
        self._request("DELETE", f"v1/secret/{path}", params=params)
    
    def list_secrets(self, path: str) -> List[str]:
        """
        List secrets at the specified path.
        
        Args:
            path: Path to list secrets from
        
        Returns:
            List of secret names at the specified path
        
        Raises:
            SecureVaultError: If the operation fails
        """
        response = self._request("GET", f"v1/secret/list/{path}")
        return response.get("keys", [])
    
    def get_secret_metadata(self, path: str) -> SecretMetadata:
        """
        Get metadata for a secret.
        
        Args:
            path: Path to the secret
        
        Returns:
            Metadata for the secret
        
        Raises:
            SecureVaultNotFoundError: If the secret is not found
            SecureVaultError: If the operation fails
        """
        response = self._request("GET", f"v1/secret/metadata/{path}")
        
        # Convert version data to proper format
        versions = {}
        for ver_num, ver_data in response.get("versions", {}).items():
            version_num = int(ver_num)
            versions[version_num] = VersionMetadata(
                created_time=datetime.fromisoformat(ver_data.get("created_time", "")),
                created_by=ver_data.get("created_by", ""),
                deleted_time=datetime.fromisoformat(ver_data.get("deleted_time", "")) if ver_data.get("deleted_time") else None,
                deleted_by=ver_data.get("deleted_by"),
                is_destroyed=ver_data.get("is_destroyed", False),
                custom_metadata=ver_data.get("custom_metadata", {})
            )
        
        return SecretMetadata(
            versions=versions,
            current_version=response.get("current_version", 0),
            created_time=datetime.fromisoformat(response.get("created_time", "")),
            last_modified=datetime.fromisoformat(response.get("last_modified", ""))
        )
    
    def create_policy(self, policy: Policy) -> None:
        """
        Create a new policy.
        
        Args:
            policy: Policy to create
        
        Raises:
            SecureVaultError: If the operation fails
        """
        # Convert PolicyRule objects to dicts
        rules = []
        for rule in policy.rules:
            rules.append({
                "path": rule.path,
                "capabilities": rule.capabilities
            })
        
        # Create payload
        payload = {
            "policy": {
                "name": policy.name,
                "description": policy.description,
                "rules": rules
            }
        }
        
        self._request("POST", "v1/policies", data=payload)
    
    def get_policy(self, name: str) -> Policy:
        """
        Get a policy by name.
        
        Args:
            name:

