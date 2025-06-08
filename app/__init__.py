"""
Flask application factory for Epic FHIR Integration.

This module implements the application factory pattern, providing a clean way to
create and configure Flask applications with different settings for development,
testing, and production environments.

Features:
- Environment-based configuration
- Blueprint registration
- Extension initialization
- Error handling setup
- Logging configuration
- Security headers
- Health check endpoints
"""

import os
from typing import Optional, Dict, Any
from flask import Flask, jsonify, request, g
from werkzeug.exceptions import HTTPException

from app.config import load_config, ConfigError
from app.core.logging import setup_logging, get_logger
from app.core.exceptions import EpicFHIRError, create_error_response
from app.core.secrets import get_secret_manager

# Import blueprints
from app.auth.routes import create_auth_blueprint
from app.fhir.routes import create_fhir_blueprint
from app.hl7.routes import create_hl7_blueprint
from app.web.routes import create_web_blueprint

logger = get_logger(__name__)


def create_app(config_name: Optional[str] = None) -> Flask:
    """
    Application factory function to create and configure Flask app.
    
    Args:
        config_name: Configuration environment ('development', 'production', 'testing')
                    If None, uses FLASK_ENV environment variable
        
    Returns:
        Configured Flask application instance
        
    Raises:
        ConfigError: If configuration is invalid
    """
    logger.info("Starting Flask application creation")
    
    try:
        # Create Flask app
        app = Flask(__name__)
        
        # Load configuration
        config = load_config()
        app.config.from_object(config)
        
        # Store config object for easy access
        app.epic_config = config
        
        # Setup logging early
        setup_logging(app)
        
        # Initialize extensions
        init_extensions(app)
        
        # Register blueprints
        register_blueprints(app)
        
        # Setup error handlers
        register_error_handlers(app)
        
        # Setup request/response handlers
        setup_request_handlers(app)
        
        # Setup health check endpoints
        setup_health_endpoints(app)
        
        # Setup security headers
        setup_security_headers(app)
        
        # Log successful initialization
        logger.info(
            "Flask application created successfully",
            extra={
                'environment': config.FLASK_ENV,
                'debug': config.FLASK_DEBUG,
                'host': config.HOST,
                'port': config.PORT
            }
        )
        
        return app
        
    except Exception as e:
        logger.error(f"Failed to create Flask application: {e}")
        raise


def init_extensions(app: Flask) -> None:
    """
    Initialize Flask extensions.
    
    Args:
        app: Flask application instance
    """
    logger.debug("Initializing Flask extensions")
    
    # Initialize Secret Manager
    try:
        secret_manager = get_secret_manager(app.config.get('GCP_PROJECT_ID'))
        app.secret_manager = secret_manager
        logger.info("Secret Manager initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize Secret Manager: {e}")
        # Don't fail app creation, but log the error
    
    # Additional extensions can be initialized here
    # Example: database, cache, etc.


def register_blueprints(app: Flask) -> None:
    """
    Register application blueprints.
    
    Args:
        app: Flask application instance
    """
    logger.debug("Registering application blueprints")
    
    try:
        # Register authentication blueprint
        auth_bp = create_auth_blueprint()
        app.register_blueprint(auth_bp)
        
        # Register FHIR blueprint
        fhir_bp = create_fhir_blueprint()
        app.register_blueprint(fhir_bp, url_prefix='/fhir')
        
        # Register HL7 blueprint
        hl7_bp = create_hl7_blueprint()
        app.register_blueprint(hl7_bp, url_prefix='/hl7')
        
        # Register web interface blueprint
        web_bp = create_web_blueprint()
        app.register_blueprint(web_bp)
        
        logger.info("All blueprints registered successfully")
        
    except Exception as e:
        logger.error(f"Failed to register blueprints: {e}")
        raise


def register_error_handlers(app: Flask) -> None:
    """
    Register global error handlers.
    
    Args:
        app: Flask application instance
    """
    logger.debug("Registering error handlers")
    
    @app.errorhandler(EpicFHIRError)
    def handle_epic_fhir_error(error: EpicFHIRError):
        """Handle custom Epic FHIR errors."""
        logger.error(
            f"Epic FHIR error: {error.message}",
            extra={
                'error_code': error.error_code,
                'context': error.context,
                'request_path': request.path if request else None
            }
        )
        
        response_data = create_error_response(
            error, 
            include_traceback=app.config.get('FLASK_DEBUG', False)
        )
        
        # Determine HTTP status code based on error type
        status_code = getattr(error, 'status_code', 500)
        if hasattr(error, 'error_code'):
            if 'TOKEN_' in error.error_code:
                status_code = 401
            elif 'AUTHORIZATION' in error.error_code:
                status_code = 403
            elif 'NOT_FOUND' in error.error_code:
                status_code = 404
            elif 'VALIDATION' in error.error_code:
                status_code = 400
        
        return jsonify(response_data), status_code
    
    @app.errorhandler(HTTPException)
    def handle_http_error(error: HTTPException):
        """Handle standard HTTP errors."""
        logger.warning(
            f"HTTP error {error.code}: {error.description}",
            extra={
                'status_code': error.code,
                'request_path': request.path if request else None
            }
        )
        
        return jsonify({
            'error': error.name,
            'message': error.description,
            'status_code': error.code
        }), error.code
    
    @app.errorhandler(Exception)
    def handle_unexpected_error(error: Exception):
        """Handle unexpected errors."""
        logger.error(
            f"Unexpected error: {str(error)}",
            extra={
                'error_type': type(error).__name__,
                'request_path': request.path if request else None
            },
            exc_info=True
        )
        
        if app.config.get('FLASK_DEBUG'):
            # In debug mode, let Flask handle the error normally
            raise error
        
        return jsonify({
            'error': 'InternalServerError',
            'message': 'An unexpected error occurred',
            'status_code': 500
        }), 500


def setup_request_handlers(app: Flask) -> None:
    """
    Setup request and response handlers.
    
    Args:
        app: Flask application instance
    """
    logger.debug("Setting up request handlers")
    
    @app.before_request
    def before_request():
        """Execute before each request."""
        # Request ID is handled by logging middleware
        pass
    
    @app.after_request
    def after_request(response):
        """Execute after each request."""
        # Add CORS headers if needed
        if app.config.get('FLASK_ENV') == 'development':
            response.headers['Access-Control-Allow-Origin'] = '*'
            response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
            response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
        
        return response
    
    @app.teardown_appcontext
    def teardown_appcontext(error):
        """Clean up after request context."""
        # Clean up any request-specific resources
        if error:
            logger.error(f"Request teardown error: {error}")


def setup_health_endpoints(app: Flask) -> None:
    """
    Setup health check and monitoring endpoints.
    
    Args:
        app: Flask application instance
    """
    logger.debug("Setting up health check endpoints")
    
    @app.route('/health', methods=['GET'])
    def health_check():
        """Basic health check endpoint."""
        return jsonify({
            'status': 'healthy',
            'timestamp': '2024-12-05T14:30:22Z',
            'version': '1.0.0',
            'environment': app.config.get('FLASK_ENV', 'unknown')
        })
    
    @app.route('/health/detailed', methods=['GET'])
    def detailed_health_check():
        """Detailed health check with dependency status."""
        health_data = {
            'status': 'healthy',
            'timestamp': '2024-12-05T14:30:22Z',
            'version': '1.0.0',
            'environment': app.config.get('FLASK_ENV', 'unknown'),
            'checks': {}
        }
        
        overall_healthy = True
        
        # Check Secret Manager
        try:
            if hasattr(app, 'secret_manager'):
                sm_healthy = app.secret_manager.health_check()
                health_data['checks']['secret_manager'] = {
                    'status': 'healthy' if sm_healthy else 'unhealthy',
                    'details': 'GCP Secret Manager connectivity'
                }
                if not sm_healthy:
                    overall_healthy = False
            else:
                health_data['checks']['secret_manager'] = {
                    'status': 'unavailable',
                    'details': 'Secret Manager not initialized'
                }
        except Exception as e:
            health_data['checks']['secret_manager'] = {
                'status': 'error',
                'details': str(e)
            }
            overall_healthy = False
        
        # Check configuration
        try:
            config_checks = {
                'epic_base_url': bool(app.config.get('EPIC_BASE_URL')),
                'gcp_project_id': bool(app.config.get('GCP_PROJECT_ID')),
                'secret_key': bool(app.config.get('SECRET_KEY'))
            }
            
            config_healthy = all(config_checks.values())
            health_data['checks']['configuration'] = {
                'status': 'healthy' if config_healthy else 'unhealthy',
                'details': config_checks
            }
            
            if not config_healthy:
                overall_healthy = False
                
        except Exception as e:
            health_data['checks']['configuration'] = {
                'status': 'error',
                'details': str(e)
            }
            overall_healthy = False
        
        # Set overall status
        health_data['status'] = 'healthy' if overall_healthy else 'unhealthy'
        
        status_code = 200 if overall_healthy else 503
        return jsonify(health_data), status_code
    
    @app.route('/metrics', methods=['GET'])
    def metrics():
        """Basic metrics endpoint for monitoring."""
        # This could be expanded to include Prometheus metrics
        return jsonify({
            'requests_total': 'counter metric would go here',
            'request_duration': 'histogram metric would go here',
            'active_sessions': 'gauge metric would go here'
        })


def setup_security_headers(app: Flask) -> None:
    """
    Setup security headers for all responses.
    
    Args:
        app: Flask application instance
    """
    logger.debug("Setting up security headers")
    
    @app.after_request
    def add_security_headers(response):
        """Add security headers to all responses."""
        # Only add security headers in production
        if app.config.get('FLASK_ENV') == 'production':
            response.headers['X-Content-Type-Options'] = 'nosniff'
            response.headers['X-Frame-Options'] = 'DENY'
            response.headers['X-XSS-Protection'] = '1; mode=block'
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
            response.headers['Content-Security-Policy'] = "default-src 'self'"
        
        # Always add these headers
        response.headers['X-Powered-By'] = 'Epic FHIR Integration'
        
        return response


def create_wsgi_app() -> Flask:
    """
    Create WSGI application for production deployment.
    
    Returns:
        Configured Flask application
    """
    return create_app()


# JWKS endpoint (moved from original app.py)
def setup_jwks_endpoint(app: Flask) -> None:
    """
    Setup JWKS endpoint for OAuth2 key distribution.
    
    Args:
        app: Flask application instance
    """
    @app.route('/.well-known/jwks.json')
    def jwks():
        """JWKS endpoint for OAuth2 public keys."""
        try:
            from app.auth.token_manager import load_jwks
            return jsonify(load_jwks())
        except Exception as e:
            logger.error(f"Failed to load JWKS: {e}")
            return jsonify({'error': 'Failed to load JWKS'}), 500


# Development server runner
def run_development_server(app: Flask) -> None:
    """
    Run development server with SSL if certificates are available.
    
    Args:
        app: Flask application instance
    """
    ssl_context = app.epic_config.get_ssl_context()
    
    if ssl_context:
        logger.info(f"Starting development server with SSL on {app.epic_config.HOST}:{app.epic_config.PORT}")
        app.run(
            debug=app.epic_config.FLASK_DEBUG,
            host=app.epic_config.HOST,
            port=app.epic_config.PORT,
            ssl_context=ssl_context
        )
    else:
        logger.warning("SSL certificates not found, starting without SSL")
        app.run(
            debug=app.epic_config.FLASK_DEBUG,
            host=app.epic_config.HOST,
            port=8080 if app.epic_config.PORT == 443 else app.epic_config.PORT
        )


if __name__ == '__main__':
    # This allows running the app directly for development
    app = create_app()
    run_development_server(app)