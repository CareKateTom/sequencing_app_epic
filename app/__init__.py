"""
Flask application factory for Epic FHIR Integration.

Healthcare-focused application factory prioritizing security, compliance, and auditability.
Follows the principle: "Secure and compliant, not enterprise-ready"
"""

import os
from flask import Flask, request, g
from werkzeug.exceptions import HTTPException

from app.config import load_config
from app.core.logging import setup_logging, get_logger, log_security_event
from app.core.exceptions import EpicFHIRError
from app.core.secrets import get_secret_manager

# Import blueprints
from app.auth.routes import create_auth_blueprint
from app.fhir.routes import create_fhir_blueprint
from app.hl7.routes import create_hl7_blueprint
from app.web.routes import create_web_blueprint

logger = get_logger(__name__)


def create_app() -> Flask:
    """
    Create and configure Flask application for Epic FHIR Integration.
    
    Focuses on security, compliance, and audit logging for healthcare environments.
    
    Returns:
        Configured Flask application instance
    """
    logger.info("Creating Epic FHIR Integration application")
    
    # Create Flask app
    app = Flask(__name__)
    
    # Load configuration
    config = load_config()
    app.config.from_mapping(vars(config))
    
    # Setup structured logging early
    setup_logging(app)
    
    # Initialize core services
    init_secret_manager(app)
    
    # Register blueprints
    register_blueprints(app)
    
    # Setup security and compliance handlers
    setup_security_handlers(app)
    
    logger.info(
        "Epic FHIR Integration application created",
        extra={
            'environment': config.FLASK_ENV,
            'host': config.HOST,
            'port': config.PORT
        }
    )
    
    return app


def init_secret_manager(app: Flask) -> None:
    """Initialize GCP Secret Manager for credential retrieval."""
    try:
        project_id = app.config.get('GCP_PROJECT_ID')
        if not project_id:
            raise ValueError("GCP_PROJECT_ID not configured")
        
        secret_manager = get_secret_manager(project_id)
        app.secret_manager = secret_manager
        
        logger.info("Secret Manager initialized")
        
    except Exception as e:
        logger.error(f"Failed to initialize Secret Manager: {e}")
        # Don't fail app creation, but log for monitoring
        log_security_event(
            'secret_manager_init_failed',
            {'error': str(e)},
            level='ERROR'
        )


def register_blueprints(app: Flask) -> None:
    """Register application blueprints."""
    try:
        # Authentication (OAuth2 with Epic)
        auth_bp = create_auth_blueprint()
        app.register_blueprint(auth_bp)
        
        # FHIR API interactions
        fhir_bp = create_fhir_blueprint()
        app.register_blueprint(fhir_bp, url_prefix='/fhir')
        
        # HL7 bidirectional messaging
        hl7_bp = create_hl7_blueprint()
        app.register_blueprint(hl7_bp, url_prefix='/hl7')
        
        # Web interface
        web_bp = create_web_blueprint()
        app.register_blueprint(web_bp)
        
        logger.info("All blueprints registered")
        
    except Exception as e:
        logger.error(f"Failed to register blueprints: {e}")
        raise


def setup_security_handlers(app: Flask) -> None:
    """Setup security, error handling, and audit logging."""
    
    @app.before_request
    def security_before_request():
        """Security checks and audit logging for each request."""
        # Generate request ID for audit trail correlation
        import uuid
        g.request_id = str(uuid.uuid4())
        
        # Log all requests for security monitoring
        log_security_event(
            'request_received',
            {
                'request_id': g.request_id,
                'method': request.method,
                'path': request.path,
                'remote_addr': request.remote_addr,
                'user_agent': request.headers.get('User-Agent', 'Unknown')
            }
        )
    
    @app.errorhandler(EpicFHIRError)
    def handle_epic_error(error: EpicFHIRError):
        """Handle Epic FHIR specific errors with security logging."""
        log_security_event(
            'application_error',
            {
                'error_type': error.__class__.__name__,
                'error_code': error.error_code,
                'request_path': request.path,
                'request_id': getattr(g, 'request_id', 'unknown')
            },
            level='ERROR'
        )
        
        # Don't expose internal error details in production
        if app.config.get('FLASK_ENV') == 'development':
            error_detail = str(error)
        else:
            error_detail = "An error occurred processing your request"
        
        return {'error': error_detail}, 500
    
    @app.errorhandler(HTTPException)
    def handle_http_error(error: HTTPException):
        """Handle HTTP errors with audit logging."""
        # Log 4xx errors for security monitoring
        if error.code >= 400:
            log_security_event(
                'http_error',
                {
                    'status_code': error.code,
                    'request_path': request.path,
                    'request_id': getattr(g, 'request_id', 'unknown')
                },
                level='WARNING' if error.code < 500 else 'ERROR'
            )
        
        return {'error': error.description}, error.code
    
    @app.errorhandler(Exception)
    def handle_unexpected_error(error: Exception):
        """Handle unexpected errors with security logging."""
        log_security_event(
            'unexpected_error',
            {
                'error_type': type(error).__name__,
                'request_path': request.path,
                'request_id': getattr(g, 'request_id', 'unknown')
            },
            level='ERROR'
        )
        
        logger.error(f"Unexpected error: {error}", exc_info=True)
        
        # Never expose internal errors in production
        if app.config.get('FLASK_ENV') == 'development':
            raise error
        
        return {'error': 'Internal server error'}, 500
    
    @app.after_request
    def security_after_request(response):
        """Add security headers and log response."""
        # Add basic security headers
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-Request-ID'] = getattr(g, 'request_id', 'unknown')
        
        # Log security-relevant responses
        if response.status_code >= 400:
            log_security_event(
                'response_sent',
                {
                    'status_code': response.status_code,
                    'request_path': request.path,
                    'request_id': getattr(g, 'request_id', 'unknown')
                }
            )
        
        return response


def run_development_server(app: Flask) -> None:
    """Run development server with SSL if available."""
    ssl_context = app.config.get_ssl_context() if hasattr(app.config, 'get_ssl_context') else None
    
    if ssl_context:
        logger.info(f"Starting development server with SSL on {app.config['HOST']}:{app.config['PORT']}")
        app.run(
            debug=app.config['FLASK_DEBUG'],
            host=app.config['HOST'],
            port=app.config['PORT'],
            ssl_context=ssl_context
        )
    else:
        logger.warning("SSL certificates not found, starting without SSL")
        app.run(
            debug=app.config['FLASK_DEBUG'],
            host=app.config['HOST'],
            port=8080 if app.config['PORT'] == 443 else app.config['PORT']
        )


# JWKS endpoint for OAuth2 (required for Epic integration)
def setup_jwks_endpoint(app: Flask) -> None:
    """Setup JWKS endpoint for OAuth2 public key distribution."""
    @app.route('/.well-known/jwks.json')
    def jwks():
        """JWKS endpoint for OAuth2 public keys."""
        try:
            from app.auth.token_manager import load_jwks
            return load_jwks()
        except Exception as e:
            logger.error(f"Failed to load JWKS: {e}")
            log_security_event(
                'jwks_error',
                {'error': str(e)},
                level='ERROR'
            )
            return {'error': 'JWKS unavailable'}, 500


if __name__ == '__main__':
    # Direct execution for development
    app = create_app()
    setup_jwks_endpoint(app)
    run_development_server(app)