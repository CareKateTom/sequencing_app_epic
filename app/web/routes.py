"""
Web interface routes for Epic FHIR Integration application.

Healthcare-focused web routes prioritizing security, compliance, and user experience.
Follows principle: "Secure and compliant, not enterprise-ready"
"""

from flask import Blueprint, render_template, session, redirect, url_for, request, jsonify, current_app
from typing import Dict, Any, Optional

from app.core.logging import get_logger, log_security_event, create_audit_log
from app.auth.decorators import require_valid_token, get_current_user, is_authenticated

logger = get_logger(__name__)


def create_web_blueprint() -> Blueprint:
    """
    Create and configure the web interface blueprint.
    
    Returns:
        Configured Flask blueprint for web routes
    """
    bp = Blueprint('web', __name__)
    
    # Main application routes
    bp.add_url_rule('/', 'index', index, methods=['GET'])
    bp.add_url_rule('/menu', 'menu', menu, methods=['GET'])
    bp.add_url_rule('/about', 'about', about, methods=['GET'])
    bp.add_url_rule('/help', 'help_page', help_page, methods=['GET'])
    
    logger.info("Web blueprint created with all routes registered")
    return bp


def index():
    """Main landing page for the Epic FHIR Integration application."""
    try:
        # Simple check for authentication
        if is_authenticated():
            return redirect(url_for('web.menu'))
        
        # Simple template rendering
        return render_template('web/index.html')
        
    except Exception as e:
        logger.error(f"Error rendering index page: {e}")
        return render_template(
            'web/error.html',
            error_title='Application Error',
            error_message='Unable to load the application homepage.'
        ), 500


@require_valid_token
def menu(token: Dict[str, Any]):
    """
    Main application menu for authenticated users.
    
    Shows available functionality based on user's Epic context and permissions.
    
    Args:
        token: OAuth2 token from decorator
        
    Returns:
        Rendered menu template with available options
    """
    try:
        # Get user context from session
        epic_user_id = session.get('epic_user_id')
        launch_type = session.get('launch_type', 'unknown')
        fhir_server = session.get('iss')
        
        # Get Epic endpoints availability
        has_get_message = bool(session.get('get_message_url'))
        has_set_message = bool(session.get('set_message_url'))
        
        # Determine available features based on context
        features = {
            'fhir_access': bool(token and fhir_server),
            'patient_search': bool(token and fhir_server),
            'bidirectional_hl7': has_get_message or has_set_message,
            'get_message': has_get_message,
            'set_message': has_set_message,
            'api_testing': bool(token and fhir_server)
        }
        
        # Get token information for display
        token_info = {
            'scopes': token.get('scope', '').split() if token.get('scope') else [],
            'expires_in_minutes': _calculate_token_expiry_minutes(token),
            'epic_user_id': epic_user_id,
            'launch_type': launch_type
        }
        
        # Log menu access
        create_audit_log(
            action='menu_access',
            resource='application_menu',
            user_id=epic_user_id,
            details={
                'launch_type': launch_type,
                'features_available': features,
                'fhir_server': fhir_server
            }
        )
        
        logger.info(
            "Menu page accessed",
            extra={
                'epic_user_id': epic_user_id,
                'launch_type': launch_type,
                'features_enabled': sum(features.values())
            }
        )
        
        return render_template(
            'web/menu.html',
            token_info=token_info,
            features=features,
            fhir_server=fhir_server,
            launch_type=launch_type,
            epic_user_id=epic_user_id
        )
        
    except Exception as e:
        logger.error(f"Error rendering menu page: {e}")
        return render_template(
            'web/error.html',
            error_title='Menu Error',
            error_message='Unable to load the application menu.',
            error_code=500
        ), 500


def about():
    """
    About page with application information and Epic integration details.
    
    Returns:
        Rendered about template
    """
    try:
        # Get application configuration for display
        app_info = {
            'version': current_app.config.get('VERSION', '1.0.0'),
            'environment': current_app.config.get('FLASK_ENV', 'production'),
            'epic_base_url': current_app.config.get('EPIC_BASE_URL', ''),
            'project_id': current_app.config.get('GCP_PROJECT_ID', '')
        }
        
        # Get authentication status
        auth_status = {
            'is_authenticated': is_authenticated(),
            'epic_user_id': session.get('epic_user_id') if is_authenticated() else None,
            'launch_type': session.get('launch_type') if is_authenticated() else None
        }
        
        # Log page access
        log_security_event(
            'about_page_accessed',
            {
                'is_authenticated': auth_status['is_authenticated'],
                'epic_user_id': auth_status['epic_user_id']
            }
        )
        
        return render_template(
            'web/about.html',
            app_info=app_info,
            auth_status=auth_status
        )
        
    except Exception as e:
        logger.error(f"Error rendering about page: {e}")
        return render_template(
            'web/error.html',
            error_title='About Page Error',
            error_message='Unable to load application information.',
            error_code=500
        ), 500


def help_page():
    """
    Help and documentation page for users.
    
    Returns:
        Rendered help template
    """
    try:
        # Get authentication context for help content
        is_auth = is_authenticated()
        epic_user_id = session.get('epic_user_id') if is_auth else None
        
        # Determine help content based on authentication status
        help_sections = {
            'getting_started': True,
            'epic_launch': True,
            'patient_search': is_auth,
            'hl7_messaging': is_auth and bool(session.get('get_message_url') or session.get('set_message_url')),
            'api_testing': is_auth,
            'troubleshooting': True
        }
        
        # Get configuration for help content
        help_config = {
            'epic_base_url': current_app.config.get('EPIC_BASE_URL', ''),
            'support_contact': current_app.config.get('SUPPORT_CONTACT', 'support@example.com'),
            'documentation_url': current_app.config.get('DOCUMENTATION_URL', '#')
        }
        
        # Log help page access
        log_security_event(
            'help_page_accessed',
            {
                'is_authenticated': is_auth,
                'epic_user_id': epic_user_id,
                'sections_available': sum(help_sections.values())
            }
        )
        
        return render_template(
            'web/help.html',
            help_sections=help_sections,
            help_config=help_config,
            is_authenticated=is_auth
        )
        
    except Exception as e:
        logger.error(f"Error rendering help page: {e}")
        return render_template(
            'web/error.html',
            error_title='Help Page Error',
            error_message='Unable to load help documentation.',
            error_code=500
        ), 500


# Helper Functions

def _calculate_token_expiry_minutes(token: Dict[str, Any]) -> Optional[int]:
    """
    Calculate minutes until token expiry.
    
    Args:
        token: OAuth2 token dictionary
        
    Returns:
        Minutes until expiry or None if cannot determine
    """
    try:
        if 'expires_at' in token:
            from datetime import datetime
            expires_at = datetime.fromtimestamp(token['expires_at'])
            now = datetime.now()
            delta = expires_at - now
            return max(0, int(delta.total_seconds() // 60))
        
        elif 'expires_in' in token and 'created_at' in token:
            from datetime import datetime, timedelta
            created_at_str = token['created_at']
            
            if isinstance(created_at_str, str):
                created_at = datetime.fromisoformat(created_at_str.replace('Z', '+00:00'))
            else:
                created_at = created_at_str
            
            expires_at = created_at + timedelta(seconds=token['expires_in'])
            now = datetime.now(expires_at.tzinfo) if expires_at.tzinfo else datetime.now()
            delta = expires_at - now
            return max(0, int(delta.total_seconds() // 60))
        
    except Exception as e:
        logger.warning(f"Failed to calculate token expiry: {e}")
    
    return None


def _get_feature_status(token: Dict[str, Any]) -> Dict[str, Any]:
    """
    Determine which application features are available based on current context.
    
    Args:
        token: OAuth2 token dictionary
        
    Returns:
        Dictionary of feature availability status
    """
    # Check basic authentication
    has_token = bool(token)
    has_fhir_server = bool(session.get('iss'))
    
    # Check Epic endpoints
    has_get_message = bool(session.get('get_message_url'))
    has_set_message = bool(session.get('set_message_url'))
    
    # Check scopes
    scopes = set(token.get('scope', '').split()) if token.get('scope') else set()
    
    return {
        'basic_auth': has_token,
        'fhir_access': has_token and has_fhir_server,
        'patient_read': 'patient/Patient.read' in scopes or 'Patient.read' in scopes,
        'patient_search': has_token and has_fhir_server,
        'hl7_receive': has_get_message,
        'hl7_send': has_set_message,
        'bidirectional_hl7': has_get_message or has_set_message,
        'api_testing': has_token and has_fhir_server,
        'epic_context': bool(session.get('epic_user_id')),
        'ehr_launch': session.get('launch_type') == 'ehr_launch'
    }


def _get_navigation_context() -> Dict[str, Any]:
    """
    Get navigation context for templates.
    
    Returns:
        Dictionary with navigation information
    """
    is_auth = is_authenticated()
    
    nav_items = []
    
    # Always available
    nav_items.append({
        'name': 'Home',
        'url': url_for('web.index'),
        'active': request.endpoint == 'web.index'
    })
    
    if is_auth:
        nav_items.extend([
            {
                'name': 'Menu',
                'url': url_for('web.menu'),
                'active': request.endpoint == 'web.menu'
            },
            {
                'name': 'Patient Search',
                'url': url_for('fhir.search_page'),
                'active': request.endpoint in ['fhir.search_page', 'fhir.patient_search']
            },
            {
                'name': 'API Tester',
                'url': url_for('fhir.test_api'),
                'active': request.endpoint == 'fhir.test_api'
            }
        ])
        
        # Add HL7 items if available
        if session.get('get_message_url') or session.get('set_message_url'):
            nav_items.append({
                'name': 'HL7 Messages',
                'url': url_for('hl7.message_menu'),
                'active': request.endpoint.startswith('hl7.') if request.endpoint else False
            })
    
    # Always available
    nav_items.extend([
        {
            'name': 'About',
            'url': url_for('web.about'),
            'active': request.endpoint == 'web.about'
        },
        {
            'name': 'Help',
            'url': url_for('web.help_page'),
            'active': request.endpoint == 'web.help_page'
        }
    ])
    
    return {
        'nav_items': nav_items,
        'is_authenticated': is_auth,
        'epic_user_id': session.get('epic_user_id') if is_auth else None
    }


def _get_user_session_info() -> Dict[str, Any]:
    """
    Get current user session information for templates.
    
    Returns:
        Dictionary with session information
    """
    if not is_authenticated():
        return {'authenticated': False}
    
    return {
        'authenticated': True,
        'epic_user_id': session.get('epic_user_id'),
        'launch_type': session.get('launch_type'),
        'fhir_server': session.get('iss'),
        'has_hl7_endpoints': bool(session.get('get_message_url') or session.get('set_message_url')),
        'session_started': session.get('created_at'),
        'token_expires_minutes': _calculate_token_expiry_minutes(session.get('token', {}))
    }


# Template context processors for the web blueprint
def add_template_globals(bp: Blueprint):
    """Add global template variables for the web blueprint."""
    
    @bp.app_context_processor
    def inject_navigation():
        """Inject navigation context into all templates."""
        return {
            'navigation': _get_navigation_context(),
            'user_session': _get_user_session_info()
        }
    
    @bp.app_context_processor
    def inject_app_info():
        """Inject application information into templates."""
        return {
            'app_name': 'Epic FHIR Integration',
            'app_version': current_app.config.get('VERSION', '1.0.0'),
            'environment': current_app.config.get('FLASK_ENV', 'production'),
            'is_development': current_app.config.get('FLASK_ENV') == 'development'
        }


# Error handlers specific to web routes
def handle_web_error(error):
    """
    Handle errors that occur within web routes.
    
    Args:
        error: Exception that occurred
        
    Returns:
        Rendered error template
    """
    logger.error(f"Web route error: {error}", exc_info=True)
    
    # Log security event for monitoring
    log_security_event(
        'web_route_error',
        {
            'error_type': type(error).__name__,
            'error_message': str(error),
            'endpoint': request.endpoint,
            'path': request.path
        },
        level='ERROR'
    )
    
    # Determine error details
    if hasattr(error, 'code'):
        error_code = error.code
        error_title = f"HTTP {error_code} Error"
    else:
        error_code = 500
        error_title = "Application Error"
    
    return render_template(
        'web/error.html',
        error_title=error_title,
        error_message=str(error),
        error_code=error_code,
        show_home_link=True
    ), error_code


def init_web_logging():
    """Initialize web-specific logging configuration."""
    web_logger = get_logger('epic_fhir.web')
    web_logger.info("Web module logging initialized")


# Initialize logging when module is imported
init_web_logging()