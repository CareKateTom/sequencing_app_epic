"""
Flask extensions initialization for Epic FHIR Integration.

Healthcare-focused extensions prioritizing security and compliance.
Follows principle: "Secure and compliant, not enterprise-ready"
"""

from typing import Optional
from flask import Flask

from app.core.logging import get_logger, log_security_event
from app.core.secrets import GCPSecretManager
from app.core.exceptions import EpicFHIRError

logger = get_logger(__name__)

# Global extension instances
secret_manager: Optional[GCPSecretManager] = None


def init_secret_manager(app: Flask) -> GCPSecretManager:
    """
    Initialize GCP Secret Manager extension.
    
    Args:
        app: Flask application instance
        
    Returns:
        Configured GCPSecretManager instance
    """
    global secret_manager
    
    try:
        project_id = app.config.get('GCP_PROJECT_ID')
        if not project_id:
            raise EpicFHIRError("GCP_PROJECT_ID not configured")
        
        # Simple initialization - no enterprise caching, no complex config
        secret_manager = GCPSecretManager(project_id)
        
        # Store on app for easy access
        app.secret_manager = secret_manager
        
        # Log initialization for security monitoring
        log_security_event(
            'secret_manager_initialized',
            {
                'project_id': project_id,
                'success': True
            }
        )
        
        logger.info("Secret Manager extension initialized")
        return secret_manager
        
    except Exception as e:
        logger.error(f"Failed to initialize Secret Manager: {e}")
        
        # Log failure for security monitoring
        log_security_event(
            'secret_manager_init_failed',
            {
                'error': str(e),
                'project_id': app.config.get('GCP_PROJECT_ID')
            },
            level='ERROR'
        )
        
        raise EpicFHIRError(f"Failed to initialize Secret Manager: {e}")


def init_extensions(app: Flask) -> None:
    """
    Initialize all Flask extensions with the application.
    
    Args:
        app: Flask application instance
    """
    logger.debug("Initializing Flask extensions")
    
    try:
        # Initialize Secret Manager
        init_secret_manager(app)
        
        logger.info("All extensions initialized successfully")
        
    except Exception as e:
        logger.error(f"Failed to initialize extensions: {e}")
        raise


def get_secret_manager_instance() -> Optional[GCPSecretManager]:
    """
    Get the global secret manager instance.
    
    Returns:
        GCPSecretManager instance or None if not initialized
    """
    return secret_manager