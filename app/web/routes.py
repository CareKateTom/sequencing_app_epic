"""
Streamlined web interface routes for Epic HL7 Integration.

Focused on authentication and HL7 messaging workflow.
"""

from flask import Blueprint, render_template, session, redirect, url_for, request, current_app
from typing import Dict, Any

from app.core.logging import get_logger, create_audit_log
from app.auth.decorators import require_valid_token, is_authenticated

logger = get_logger(__name__)


def create_web_blueprint() -> Blueprint:
    """Create and configure the web interface blueprint."""
    bp = Blueprint('web', __name__)
    
    # Main application routes
    bp.add_url_rule('/', 'index', index, methods=['GET'])
    bp.add_url_rule('/menu', 'menu', menu, methods=['GET'])
    bp.add_url_rule('/about', 'about', about, methods=['GET'])
    
    logger.info("Web blueprint created")
    return bp


def index():
    """Main landing page for Epic HL7 Integration."""
    if is_authenticated():
        return redirect(url_for('web.menu'))
    
    return render_template('web/index.html')


@require_valid_token
def menu(token: Dict[str, Any]):
    """Main application menu for authenticated users."""
    try:
        # Get user context from session
        epic_user_id = session.get('epic_user_id')
        launch_type = session.get('launch_type', 'unknown')
        
        # Get Epic HL7 endpoints availability
        has_get_message = bool(session.get('get_message_url'))
        has_set_message = bool(session.get('set_message_url'))
        
        # Simplified features - only HL7 functionality
        features = {
            'bidirectional_hl7': has_get_message or has_set_message,
            'get_message': has_get_message,
            'set_message': has_set_message,
            'hl7_parser': True  # Always available
        }
        
        # Token information for display (removed FHIR scopes)
        token_info = {
            'expires_in_minutes': _calculate_token_expiry_minutes(token),
            'epic_user_id': epic_user_id
        }
        
        # Log menu access
        create_audit_log(
            action='menu_access',
            resource='hl7_menu',
            user_id=epic_user_id,
            details={'launch_type': launch_type, 'hl7_available': features['bidirectional_hl7']}
        )
        
        logger.info(f"HL7 menu accessed by {epic_user_id}")
        
        return render_template(
            'web/menu.html',
            token_info=token_info,
            features=features,
            launch_type=launch_type,
            epic_user_id=epic_user_id
        )
        
    except Exception as e:
        logger.error(f"Error rendering menu: {e}")
        return render_template('web/error.html', error_message='Unable to load menu'), 500


def about():
    """About page with application information."""
    app_info = {
        'version': '2.0.0',  # Updated for streamlined version
        'environment': current_app.config.get('FLASK_ENV', 'production'),
        'epic_base_url': current_app.config.get('EPIC_BASE_URL', ''),
        'focus': 'Epic HL7 Coding Interface Integration'
    }
    
    return render_template('web/about.html', app_info=app_info)


def _calculate_token_expiry_minutes(token: Dict[str, Any]):
    """Calculate minutes until token expiry."""
    try:
        if 'expires_at' in token:
            from datetime import datetime
            expires_at = datetime.fromtimestamp(token['expires_at'])
            now = datetime.now()
            delta = expires_at - now
            return max(0, int(delta.total_seconds() // 60))
    except Exception:
        pass
    return None