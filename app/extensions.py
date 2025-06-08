"""
Flask extensions initialization for Epic FHIR Integration.

This module provides a centralized way to initialize and configure Flask extensions.
Extensions are created here and then initialized with the app in the application factory.

Currently minimal since we're not using many extensions, but provides a clean
pattern for future expansion (database, caching, etc.).
"""

from typing import Optional
from flask import Flask

from app.core.logging import get_logger
from app.core.secrets import GCPSecretManager

logger = get_logger(__name__)

# Global extension instances (initialized in init_app functions)
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
            raise ValueError("GCP_PROJECT_ID not configured")
        
        secret_manager = GCPSecretManager(
            project_id=project_id,
            cache_ttl=3600,  # 1 hour cache
            enable_cache=True,
            validate_secrets=True
        )
        
        # Store on app for easy access
        app.secret_manager = secret_manager
        
        logger.info("Secret Manager extension initialized")
        return secret_manager
        
    except Exception as e:
        logger.error(f"Failed to initialize Secret Manager: {e}")
        raise


def init_extensions(app: Flask) -> None:
    """
    Initialize all Flask extensions with the application.
    
    Args:
        app: Flask application instance
    """
    logger.debug("Initializing Flask extensions")
    
    # Initialize Secret Manager
    init_secret_manager(app)
    
    # Future extensions can be added here:
    # init_database(app)
    # init_cache(app)
    # init_session(app)
    
    logger.info("All extensions initialized successfully")


def get_secret_manager_instance() -> Optional[GCPSecretManager]:
    """
    Get the global secret manager instance.
    
    Returns:
        GCPSecretManager instance or None if not initialized
    """
    return secret_manager