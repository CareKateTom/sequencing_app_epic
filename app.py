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
        
        # Get configuration
        config = app.config
        
        # Determine SSL context
        ssl_context = None
        if hasattr(config, 'get_ssl_context'):
            ssl_context = config.get_ssl_context()
        else:
            cert_path = config.get('SSL_CERT_PATH', 'certs/cert.pem')
            key_path = config.get('SSL_KEY_PATH', 'certs/key.pem')
            
            if os.path.exists(cert_path) and os.path.exists(key_path):
                ssl_context = (cert_path, key_path)
        
        # Run application
        if ssl_context:
            logger.info(f"Starting Epic FHIR Integration with SSL on {config['HOST']}:{config['PORT']}")
            logger.info("Epic callback URL: https://localhost/callback")
            
            app.run(
                debug=config.get('FLASK_DEBUG', False),
                host=config.get('HOST', 'localhost'),
                port=config.get('PORT', 443),
                ssl_context=ssl_context
            )
        else:
            logger.warning("SSL certificates not found - Epic integration requires HTTPS")
            logger.warning("Please generate SSL certificates or update certificate paths")
            
            # Run without SSL for basic testing (Epic won't work)
            port = 8080 if config.get('PORT') == 443 else config.get('PORT', 8080)
            logger.info(f"Starting without SSL on {config['HOST']}:{port}")
            
            app.run(
                debug=config.get('FLASK_DEBUG', False),
                host=config.get('HOST', 'localhost'),
                port=port
            )
            
    except Exception as e:
        logger.error(f"Failed to start application: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()