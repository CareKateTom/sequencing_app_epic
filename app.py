#!/usr/bin/env python3
"""
Entry point for Epic FHIR Integration application.

For local development and Epic EHR launch testing.
"""

import os
import sys
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from app import create_app
from app.config import load_config, load_dotenv_if_exists
from app.core.logging import get_logger

# Load environment variables from .env file
load_dotenv_if_exists()

logger = get_logger(__name__)


def main():
    """Main entry point for the application."""
    try:
        # Create Flask application
        app = create_app()
        
        # Setup JWKS endpoint for Epic integration
        from app.auth.token_manager import load_jwks
        
        @app.route('/.well-known/jwks.json')
        def jwks():
            """JWKS endpoint for OAuth2 public keys."""
            try:
                return load_jwks()
            except Exception as e:
                logger.error(f"Failed to load JWKS: {e}")
                return {'error': 'JWKS unavailable'}, 500
        
        # Get configuration from Flask's config
        config = app.config

        # Detect if running on Cloud Run vs local development
        is_cloud_run = bool(
            os.environ.get('K_SERVICE') or 
            os.environ.get('GOOGLE_CLOUD_PROJECT') or
            (os.environ.get('PORT') and os.environ.get('PORT') in ['8080', '80'])
        )
        
        # Configure host and port based on environment
        if is_cloud_run:
            port = int(os.environ.get('PORT', 8080))
            host = '0.0.0.0'
            debug = False
            ssl_context = None
            logger.info(f"Starting on Cloud Run: {host}:{port}")
        else:
            # Local development
            port = int(os.environ.get('PORT', config.get('PORT', 443)))
            configured_host = config.get('HOST', 'localhost')
            host = configured_host if configured_host != '0.0.0.0' else 'localhost'
            debug = config.get('FLASK_ENV') == 'development' and config.get('FLASK_DEBUG', False)
            
            # Setup SSL for local development
            ssl_context = None
            cert_path = config.get('SSL_CERT_PATH', 'certs/cert.pem')
            key_path = config.get('SSL_KEY_PATH', 'certs/key.pem')
            
            if os.path.exists(cert_path) and os.path.exists(key_path):
                ssl_context = (cert_path, key_path)
                logger.info(f"Starting with SSL on https://{host}:{port}")
            else:
                logger.warning("SSL certificates not found - running without SSL")
                if port == 443:
                    port = 8080
        
        # Run application
        app.run(
            debug=debug,
            host=host,
            port=port,
            ssl_context=ssl_context
        )
            
    except Exception as e:
        logger.error(f"Failed to start application: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()