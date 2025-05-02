"""
Data models for the SecureVault Python client.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Union
from datetime import datetime


@dataclass
class PolicyRule:
    """Rule defining capabilities for a specific path pattern."""
    
    path: str
    capabilities: List[str]


@dataclass
class Policy:
    """SecureVault access policy."""
    
    name: str
    description: str
    rules: List[PolicyRule]


@dataclass
class Secret:
    """Secret data with metadata."""
    
    data: Dict[str, Any]
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class VersionMetadata:
    """Metadata for a specific secret version."""
    
    created_time: datetime
    created_by: str
    deleted_time: Optional[datetime] = None
    deleted_by: Optional[str] = None
    is_destroyed: bool = False
    custom_metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SecretMetadata:
    """Metadata for a secret with version history."""
    
    versions: Dict[int, VersionMetadata]
    current_version: int
    created_time: datetime
    last_modified: datetime


@dataclass
class ReadOptions:
    """Options for reading secrets."""
    
    version: int = 0  # 0 means latest version


@dataclass
class WriteOptions:
    """Options for writing secrets."""
    
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DeleteOptions:
    """Options for deleting secrets."""
    
    versions: List[int] = field(default_factory=list)
    destroy: bool = False

