"""
GCP Secret Manager integration for Epic FHIR Integration application.

Healthcare-focused secret management prioritizing security and compliance.
Follows principle: "Secure and compliant, not enterprise-ready"
"""

import os
from typing import Optional
from google.cloud import secretmanager
from google.api_core.exceptions import NotFound, PermissionDenied, GoogleAPIError

from app.core.exceptions import EpicHL7Error
from app.core.logging import get_logger, log_security_event

logger = get_logger(__name__)


class GCPSecretManager:
    """
    Simple GCP Secret Manager client with security logging.
    
    No caching, no performance monitoring, no enterprise features.
    Just secure secret retrieval with compliance logging.
    """
    
    def __init__(self, project_id: str):
        """
        Initialize GCP Secret Manager client.
        
        Args:
            project_id: GCP project ID
        """
        self.project_id = project_id
        
        try:
            self.client = secretmanager.SecretManagerServiceClient()
            logger.info(f"Initialized GCP Secret Manager for project: {project_id}")
        except Exception as e:
            logger.error(f"Failed to initialize Secret Manager client: {e}")
            raise EpicHL7Error(f"Failed to initialize Secret Manager: {e}")
    
    def get_secret(self, secret_id: str, version: str = "latest") -> str:
        """
        Retrieve secret from GCP Secret Manager.
        
        Args:
            secret_id: The secret ID to retrieve
            version: Secret version (default: "latest")
            
        Returns:
            The secret value as a string
            
        Raises:
            EpicHL7Error: If secret retrieval fails
        """
        try:
            # Construct the resource name
            name = f"projects/{self.project_id}/secrets/{secret_id}/versions/{version}"
            
            logger.debug(f"Retrieving secret '{secret_id}' version '{version}' from GCP")
            
            # Access the secret version
            response = self.client.access_secret_version(request={"name": name})
            secret_value = response.payload.data.decode("UTF-8")
            
            # Basic validation
            if not secret_value or not secret_value.strip():
                raise EpicHL7Error(f"Secret '{secret_id}' is empty")
            
            # Log successful access for security monitoring
            log_security_event(
                'secret_accessed',
                {
                    'secret_id': secret_id,
                    'version': version,
                    'success': True
                }
            )
            
            logger.info(f"Successfully retrieved secret '{secret_id}'")
            return secret_value
            
        except NotFound:
            error_msg = f"Secret '{secret_id}' not found in project '{self.project_id}'"
            logger.error(error_msg)
            
            # Log security event for monitoring
            log_security_event(
                'secret_not_found',
                {
                    'secret_id': secret_id,
                    'project_id': self.project_id,
                    'error': 'not_found'
                },
                level='ERROR'
            )
            
            raise EpicHL7Error(error_msg)
            
        except PermissionDenied:
            error_msg = f"Permission denied accessing secret '{secret_id}'"
            logger.error(error_msg)
            
            # Log security event - this is critical for monitoring
            log_security_event(
                'secret_access_denied',
                {
                    'secret_id': secret_id,
                    'project_id': self.project_id,
                    'error': 'permission_denied'
                },
                level='ERROR'
            )
            
            raise EpicHL7Error(error_msg)
            
        except GoogleAPIError as e:
            error_msg = f"Google API error retrieving secret '{secret_id}': {e}"
            logger.error(error_msg)
            
            log_security_event(
                'secret_api_error',
                {
                    'secret_id': secret_id,
                    'error': str(e)
                },
                level='ERROR'
            )
            
            raise EpicHL7Error(error_msg)
            
        except Exception as e:
            error_msg = f"Unexpected error retrieving secret '{secret_id}': {e}"
            logger.error(error_msg)
            
            log_security_event(
                'secret_unexpected_error',
                {
                    'secret_id': secret_id,
                    'error': str(e)
                },
                level='ERROR'
            )
            
            raise EpicHL7Error(error_msg)


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
                raise EpicHL7Error("GCP_PROJECT_ID environment variable not set")
        
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
    
    This maintains backward compatibility while using the simplified
    GCPSecretManager under the hood.
    """
    
    def __init__(self, gcp_id: str):
        """Initialize with GCP project ID."""
        self.project_id = gcp_id
        self.secret_manager = GCPSecretManager(gcp_id)
    
    def get_secret(self, secret_id: str) -> str:
        """Get secret - maintains original interface."""
        return self.secret_manager.get_secret(secret_id)