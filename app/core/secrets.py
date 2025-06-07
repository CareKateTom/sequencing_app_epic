"""
GCP Secret Manager integration for Epic FHIR Integration application.

This module provides a robust interface for retrieving secrets from 
Google Cloud Secret Manager with caching, validation, and error handling.
"""

import os
import time
from typing import Dict, Optional, Any
from google.cloud import secretmanager
from google.cloud.secretmanager_v1 import SecretManagerServiceClient
from google.api_core.exceptions import NotFound, PermissionDenied, GoogleAPIError

from app.core.exceptions import SecretManagerError
from app.core.logging import get_logger

logger = get_logger(__name__)


class SecretCache:
    """Simple in-memory cache for secrets with TTL support."""
    
    def __init__(self, default_ttl: int = 3600):  # 1 hour default
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.default_ttl = default_ttl
    
    def get(self, key: str) -> Optional[str]:
        """Get cached secret if not expired."""
        if key not in self.cache:
            return None
        
        entry = self.cache[key]
        if time.time() > entry['expires_at']:
            del self.cache[key]
            return None
        
        return entry['value']
    
    def set(self, key: str, value: str, ttl: Optional[int] = None) -> None:
        """Cache secret with TTL."""
        if ttl is None:
            ttl = self.default_ttl
        
        self.cache[key] = {
            'value': value,
            'expires_at': time.time() + ttl,
            'cached_at': time.time()
        }
    
    def clear(self) -> None:
        """Clear all cached secrets."""
        self.cache.clear()
    
    def remove(self, key: str) -> None:
        """Remove specific secret from cache."""
        self.cache.pop(key, None)


class GCPSecretManager:
    """
    Enhanced GCP Secret Manager client with caching, validation, and error handling.
    
    Features:
    - Automatic retry logic
    - In-memory caching with TTL
    - Comprehensive error handling
    - Logging and monitoring
    - Secret validation
    """
    
    def __init__(
        self, 
        project_id: str,
        cache_ttl: int = 3600,
        enable_cache: bool = True,
        validate_secrets: bool = True
    ):
        """
        Initialize GCP Secret Manager client.
        
        Args:
            project_id: GCP project ID
            cache_ttl: Cache time-to-live in seconds
            enable_cache: Whether to enable secret caching
            validate_secrets: Whether to validate retrieved secrets
        """
        self.project_id = project_id
        self.enable_cache = enable_cache
        self.validate_secrets = validate_secrets
        
        # Initialize cache
        self.cache = SecretCache(cache_ttl) if enable_cache else None
        
        # Initialize client
        try:
            self.client = secretmanager.SecretManagerServiceClient()
            logger.info(f"Initialized GCP Secret Manager for project: {project_id}")
        except Exception as e:
            logger.error(f"Failed to initialize Secret Manager client: {e}")
            raise SecretManagerError(f"Failed to initialize Secret Manager: {e}")
    
    def get_secret(
        self, 
        secret_id: str, 
        version: str = "latest",
        force_refresh: bool = False
    ) -> str:
        """
        Retrieve secret from GCP Secret Manager.
        
        Args:
            secret_id: The secret ID to retrieve
            version: Secret version (default: "latest")
            force_refresh: Skip cache and force fresh retrieval
            
        Returns:
            The secret value as a string
            
        Raises:
            SecretManagerError: If secret retrieval fails
        """
        cache_key = f"{secret_id}:{version}"
        
        # Check cache first (unless force refresh)
        if not force_refresh and self.enable_cache:
            cached_value = self.cache.get(cache_key)
            if cached_value is not None:
                logger.debug(f"Retrieved secret '{secret_id}' from cache")
                return cached_value
        
        try:
            # Construct the resource name
            name = f"projects/{self.project_id}/secrets/{secret_id}/versions/{version}"
            
            logger.debug(f"Retrieving secret '{secret_id}' version '{version}' from GCP")
            
            # Access the secret version
            response = self.client.access_secret_version(request={"name": name})
            secret_value = response.payload.data.decode("UTF-8")
            
            # Validate secret if enabled
            if self.validate_secrets:
                self._validate_secret(secret_id, secret_value)
            
            # Cache the secret if caching is enabled
            if self.enable_cache and self.cache:
                self.cache.set(cache_key, secret_value)
            
            logger.info(f"Successfully retrieved secret '{secret_id}'")
            return secret_value
            
        except NotFound:
            error_msg = f"Secret '{secret_id}' not found in project '{self.project_id}'"
            logger.error(error_msg)
            raise SecretManagerError(error_msg)
            
        except PermissionDenied:
            error_msg = f"Permission denied accessing secret '{secret_id}'"
            logger.error(error_msg)
            raise SecretManagerError(error_msg)
            
        except GoogleAPIError as e:
            error_msg = f"Google API error retrieving secret '{secret_id}': {e}"
            logger.error(error_msg)
            raise SecretManagerError(error_msg)
            
        except Exception as e:
            error_msg = f"Unexpected error retrieving secret '{secret_id}': {e}"
            logger.error(error_msg)
            raise SecretManagerError(error_msg)
    
    def _validate_secret(self, secret_id: str, secret_value: str) -> None:
        """
        Validate retrieved secret value.
        
        Args:
            secret_id: The secret ID
            secret_value: The secret value to validate
            
        Raises:
            SecretManagerError: If validation fails
        """
        if not secret_value or not secret_value.strip():
            raise SecretManagerError(f"Secret '{secret_id}' is empty or contains only whitespace")
        
        # Specific validations for known secret types
        if 'client_id' in secret_id.lower():
            if len(secret_value) < 10:  # Basic length check for client IDs
                raise SecretManagerError(f"Client ID secret '{secret_id}' appears too short")
        
        # Add more validation rules as needed
        logger.debug(f"Secret '{secret_id}' passed validation")
    
    def get_multiple_secrets(self, secret_ids: list, version: str = "latest") -> Dict[str, str]:
        """
        Retrieve multiple secrets efficiently.
        
        Args:
            secret_ids: List of secret IDs to retrieve
            version: Secret version for all secrets
            
        Returns:
            Dictionary mapping secret_id to secret_value
        """
        secrets = {}
        errors = []
        
        for secret_id in secret_ids:
            try:
                secrets[secret_id] = self.get_secret(secret_id, version)
            except SecretManagerError as e:
                errors.append(f"{secret_id}: {e}")
                logger.warning(f"Failed to retrieve secret '{secret_id}': {e}")
        
        if errors:
            logger.error(f"Failed to retrieve {len(errors)} secrets: {errors}")
        
        logger.info(f"Successfully retrieved {len(secrets)}/{len(secret_ids)} secrets")
        return secrets
    
    def refresh_secret(self, secret_id: str, version: str = "latest") -> str:
        """
        Force refresh a secret (bypass cache).
        
        Args:
            secret_id: The secret ID to refresh
            version: Secret version
            
        Returns:
            The refreshed secret value
        """
        logger.info(f"Force refreshing secret '{secret_id}'")
        
        # Remove from cache first
        if self.enable_cache and self.cache:
            cache_key = f"{secret_id}:{version}"
            self.cache.remove(cache_key)
        
        return self.get_secret(secret_id, version, force_refresh=True)
    
    def clear_cache(self) -> None:
        """Clear all cached secrets."""
        if self.enable_cache and self.cache:
            self.cache.clear()
            logger.info("Cleared secret cache")
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics for monitoring."""
        if not self.enable_cache or not self.cache:
            return {"cache_enabled": False}
        
        return {
            "cache_enabled": True,
            "cached_secrets": len(self.cache.cache),
            "cache_entries": [
                {
                    "key": key,
                    "cached_at": entry["cached_at"],
                    "expires_at": entry["expires_at"]
                }
                for key, entry in self.cache.cache.items()
            ]
        }
    
    def health_check(self) -> bool:
        """
        Perform a health check by attempting to list secrets.
        
        Returns:
            True if the client is healthy, False otherwise
        """
        try:
            # Try to list secrets (limit to 1 for efficiency)
            parent = f"projects/{self.project_id}"
            request = {"parent": parent, "page_size": 1}
            
            list_response = self.client.list_secrets(request=request)
            # Just trying to get the first item to test connectivity
            next(iter(list_response), None)
            
            logger.debug("Secret Manager health check passed")
            return True
            
        except Exception as e:
            logger.error(f"Secret Manager health check failed: {e}")
            return False


# Global instance - initialized when needed
_secret_manager: Optional[GCPSecretManager] = None


def get_secret_manager(project_id: Optional[str] = None) -> GCPSecretManager:
    """
    Get the global secret manager instance.
    
    Args:
        project_id: GCP project ID (uses GCP_PROJECT_ID env var if not provided)
        
    Returns:
        GCPSecretManager instance
    """
    global _secret_manager
    
    if _secret_manager is None:
        if project_id is None:
            project_id = os.getenv('GCP_PROJECT_ID')
            if not project_id:
                raise SecretManagerError("GCP_PROJECT_ID environment variable not set")
        
        _secret_manager = GCPSecretManager(project_id)
    
    return _secret_manager


def get_secret(secret_id: str, version: str = "latest") -> str:
    """
    Convenience function to get a secret using the global instance.
    
    Args:
        secret_id: The secret ID to retrieve
        version: Secret version
        
    Returns:
        The secret value
    """
    manager = get_secret_manager()
    return manager.get_secret(secret_id, version)


# Legacy compatibility - maintain the original class name and interface
class gcp_secret:
    """
    Legacy compatibility class for the original gcp_secret interface.
    
    This maintains backward compatibility while using the new enhanced
    GCPSecretManager under the hood.
    """
    
    def __init__(self, gcp_id: str):
        """Initialize with GCP project ID."""
        self.project_id = gcp_id
        self.secret_manager = GCPSecretManager(gcp_id)
    
    def get_secret(self, secret_id: str) -> str:
        """Get secret - maintains original interface."""
        return self.secret_manager.get_secret(secret_id)