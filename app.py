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
        
        # Get configuration from Flask's config (already loaded in create_app)
        config = app.config

        # CLOUD RUN READY: Port and host configuration
        port = int(os.environ.get('PORT', config.get('PORT', 8080)))
        host = '0.0.0.0' if os.environ.get('PORT') else config.get('HOST', 'localhost')
        debug = config.get('FLASK_ENV') == 'development' and config.get('FLASK_DEBUG', False)
        
        # SSL handling: Cloud Run provides HTTPS termination, local dev may use SSL
        ssl_context = None
        if not os.environ.get('PORT'):  # Local development
            cert_path = config.get('SSL_CERT_PATH', 'certs/cert.pem')
            key_path = config.get('SSL_KEY_PATH', 'certs/key.pem')
            
            if os.path.exists(cert_path) and os.path.exists(key_path):
                ssl_context = (cert_path, key_path)
                logger.info(f"Starting with SSL on {host}:{port}")
            else:
                logger.warning("SSL certificates not found - running without SSL")
        else:
            logger.info(f"Starting on Cloud Run: {host}:{port} (HTTPS handled by Cloud Run)")
        
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