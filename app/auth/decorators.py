"""
Authentication decorators for Epic FHIR Integration.

Healthcare-focused decorators prioritizing security and compliance over enterprise features.
Follows principle: "Secure and compliant, not enterprise-ready"
"""

from functools import wraps
from typing import Callable, Optional, Dict, Any
from flask import session, redirect, url_for, request, g, current_app, jsonify

from app.core.exceptions import TokenRevokedException, AuthenticationError
from app.core.logging import get_logger, log_security_event
from app.core.secrets import get_secret_manager
from app.auth.token_manager import get_token_manager

logger = get_logger(__name__)


def require_valid_token(f: Callable) -> Callable:
    """
    Decorator to require valid OAuth2 token for route access.
    
    Handles token validation, automatic refresh, and revocation detection.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            # Get valid token (with auto-refresh)
            token = _get_valid_token()
            
            # Store in request context
            g.token = token
            g.epic_user_id = token.get('epicUserID')
            
            # Store Epic endpoints if available
            g.get_message_url = token.get('getMessage') or session.get('get_message_url')
            g.set_message_url = token.get('setMessage') or session.get('set_message_url')
            
            # Call original function with token
            kwargs['token'] = token
            return f(*args, **kwargs)
            
        except TokenRevokedException:
            return _handle_token_revocation()
            
        except AuthenticationError:
            return _handle_auth_error()
            
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return _handle_auth_error()
                
    return decorated_function


def require_epic_launch(f: Callable) -> Callable:
    """
    Decorator for routes requiring Epic EHR launch context.
    
    Ensures route was accessed through Epic and has bidirectional endpoints.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            # Check Epic launch context
            if not session.get('launch') or not session.get('iss'):
                log_security_event(
                    'missing_epic_context',
                    {'path': request.path}
                )
                return redirect(url_for('auth.error', error='missing_epic_context'))
            
            # Get valid token
            token = _get_valid_token()
            
            # Store Epic context
            g.token = token
            g.epic_user_id = token.get('epicUserID')
            g.fhir_server = session.get('iss')
            g.get_message_url = token.get('getMessage') or session.get('get_message_url')
            g.set_message_url = token.get('setMessage') or session.get('set_message_url')
            
            kwargs['token'] = token
            return f(*args, **kwargs)
            
        except Exception as e:
            logger.error(f"Epic launch validation failed: {e}")
            return redirect(url_for('auth.error', error='epic_validation_failed'))
                
    return decorated_function


def require_epic_endpoint(endpoint_type: str):
    """
    Simplified decorator to require specific Epic endpoints.
    
    Args:
        endpoint_type: 'getMessage' or 'setMessage'
    """
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                # Get token from session
                token = session.get('token')
                if not token:
                    logger.warning(f"No token found for {endpoint_type} endpoint check")
                    raise AuthenticationError("No authentication token found")
                
                # Look for endpoint URL in multiple places
                endpoint_url = None
                
                # Method 1: Direct from token
                endpoint_url = token.get(endpoint_type)
                
                # Method 2: From session with standard naming
                if not endpoint_url:
                    if endpoint_type == 'getMessage':
                        endpoint_url = session.get('get_message_url')
                    elif endpoint_type == 'setMessage':
                        endpoint_url = session.get('set_message_url')
                
                # Debug logging
                logger.info(f"Endpoint check for {endpoint_type}: URL={endpoint_url is not None}")
                
                if not endpoint_url:
                    # Log what we actually have for debugging
                    logger.warning(f"Missing {endpoint_type} endpoint. Token keys: {list(token.keys())}")
                    logger.warning(f"Session message URLs: getMessage={session.get('get_message_url') is not None}, setMessage={session.get('set_message_url') is not None}")
                    
                    error_msg = f"Epic {endpoint_type} endpoint not available"
                    
                    if request.is_json:
                        return jsonify({'error': error_msg}), 400
                    else:
                        return redirect(url_for('auth.error', error='missing_endpoint', details=error_msg))
                
                # Store endpoint URL in request context
                setattr(g, f'{endpoint_type.lower()}_url', endpoint_url)
                
                # Call the original function
                return f(*args, **kwargs)
                
            except Exception as e:
                logger.error(f"Decorator error for {endpoint_type}: {str(e)}")
                
                if request.is_json:
                    return jsonify({'error': 'Endpoint check failed'}), 500
                else:
                    return redirect(url_for('auth.error', error='endpoint_check_failed'))
                
        return decorated_function
    return decorator


# Helper Functions

def _get_valid_token() -> Dict[str, Any]:
    """Get valid token from session with automatic refresh."""
    token = session.get('token')
    
    if not token:
        log_security_event('missing_token', {'path': request.path})
        raise AuthenticationError("No authentication token found")
    
    # Check if token needs refresh
    token_manager = get_token_manager()
    
    if token_manager.is_token_expired(token):
        try:
            # Get refresh components
            client_id = _get_epic_client_id()
            token_endpoint = _get_token_endpoint()
            
            # Refresh token
            new_token, was_refreshed = token_manager.refresh_token_if_needed(
                token, client_id, token_endpoint
            )
            
            if was_refreshed:
                session['token'] = new_token
                logger.info("Token refreshed successfully")
                return new_token
            
            return token
            
        except TokenRevokedException:
            _clear_auth_session()
            raise
            
        except Exception as e:
            logger.error(f"Token refresh failed: {e}")
            raise AuthenticationError(f"Token refresh failed: {e}")
    
    # Validate token structure
    if not token_manager.validate_token(token):
        raise AuthenticationError("Invalid token")
    
    return token


def _handle_token_revocation() -> Any:
    """Handle token revocation by clearing session and redirecting."""
    logger.warning("Token revoked - clearing session")
    
    log_security_event(
        'token_revoked_handled',
        {'path': request.path}
    )
    
    _clear_auth_session()
    session['token_revoked'] = True
    
    return redirect(url_for('auth.launch'))


def _handle_auth_error() -> Any:
    """Handle authentication errors."""
    log_security_event(
        'authentication_error',
        {'path': request.path}
    )
    
    _clear_auth_session()
    
    if request.is_json:
        return {'error': 'Authentication required'}, 401
    else:
        return redirect(url_for('auth.launch'))


def _clear_auth_session() -> None:
    """Clear authentication-related session data."""
    auth_keys = [
        'token', 'oauth_state', 'iss', 'launch', 'metadata',
        'epic_user_id', 'get_message_url', 'set_message_url'
    ]
    
    for key in auth_keys:
        session.pop(key, None)


def _get_epic_client_id() -> str:
    """Get Epic client ID from secrets."""
    try:
        secret_manager = get_secret_manager()
        client_id_secret = current_app.config.get('EPIC_CLIENT_ID_SECRET')
        
        if not client_id_secret:
            raise AuthenticationError("EPIC_CLIENT_ID_SECRET not configured")
        
        return secret_manager.get_secret(client_id_secret)
        
    except Exception as e:
        logger.error(f"Failed to get Epic client ID: {e}")
        raise AuthenticationError(f"Failed to retrieve client credentials")


def _get_token_endpoint() -> str:
    """Get token endpoint from session metadata or reconstruct from ISS."""
    # First try to get from metadata if it still exists
    metadata = session.get('metadata')
    if metadata and metadata.get('token'):
        return metadata['token']
    
    # If metadata was cleared, reconstruct from ISS
    iss = session.get('iss')
    if iss:
        # For Epic, the token endpoint follows a predictable pattern
        if 'vendorservices.epic.com' in iss:
            # Convert FHIR URL to token endpoint
            base_url = iss.replace('/api/FHIR/R4', '').replace('/api/FHIR/DSTU2', '')
            return f"{base_url}/oauth2/token"
        else:
            # Generic reconstruction - might need adjustment for other Epic instances
            base_url = iss.rstrip('/').replace('/api/FHIR/R4', '').replace('/api/FHIR/DSTU2', '')
            return f"{base_url}/oauth2/token"
    
    raise AuthenticationError("Token endpoint not available - please re-authenticate")


# Simple user info helper for templates
def get_current_user() -> Optional[str]:
    """Get current Epic user ID if authenticated."""
    return session.get('epic_user_id')


def is_authenticated() -> bool:
    """Check if user is currently authenticated with valid token."""
    try:
        token = session.get('token')
        if not token:
            return False
        
        token_manager = get_token_manager()
        return token_manager.validate_token(token) and not token_manager.is_token_expired(token)
        
    except Exception:
        return False
    
def optional_authentication():
    """
    Decorator for routes that work with or without authentication.
    
    Passes token to function if available, None otherwise.
    """
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                # Try to get valid token but don't require it
                token = session.get('token')
                if token:
                    token_manager = get_token_manager()
                    if token_manager.validate_token(token) and not token_manager.is_token_expired(token):
                        kwargs['token'] = token
                        g.token = token
                        g.epic_user_id = token.get('epicUserID')
                    else:
                        kwargs['token'] = None
                else:
                    kwargs['token'] = None
                
                return f(*args, **kwargs)
                
            except Exception as e:
                logger.warning(f"Optional authentication failed: {e}")
                kwargs['token'] = None
                return f(*args, **kwargs)
        
        return decorated_function
    return decorator


def get_current_user_info() -> Dict[str, Any]:
    """
    Get current user information for templates and API responses.
    
    Returns:
        Dictionary with user context information
    """
    if not is_authenticated():
        return {
            'authenticated': False,
            'epic_user_id': None,
            'launch_type': None
        }
    
    token = session.get('token', {})
    
    return {
        'authenticated': True,
        'epic_user_id': session.get('epic_user_id'),
        'launch_type': session.get('launch_type'),
        'fhir_server': session.get('iss'),
        'scopes': token.get('scope', '').split() if token.get('scope') else [],
        'token_expires_at': token.get('expires_at'),
        'has_epic_endpoints': bool(session.get('get_message_url') or session.get('set_message_url'))
    }