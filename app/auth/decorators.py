"""
Authentication decorators for Epic FHIR Integration routes.

This module provides decorators for protecting routes with OAuth2 authentication,
automatic token refresh, and comprehensive error handling.
"""

from functools import wraps
from typing import Callable, Optional, Dict, Any
from flask import session, redirect, url_for, request, g, current_app

from app.core.exceptions import (
    TokenRevokedException, TokenExpiredError, AuthenticationError,
    InvalidTokenError, TokenRefreshError
)
from app.core.logging import get_logger, log_security_event
from app.core.secrets import get_secret_manager
from app.auth.token_manager import get_token_manager

logger = get_logger(__name__)


def require_valid_token(
    auto_refresh: bool = True,
    require_epic_context: bool = False,
    required_scopes: Optional[list] = None
):
    """
    Decorator to require valid OAuth2 token for route access.
    
    Args:
        auto_refresh: Automatically refresh expired tokens
        require_epic_context: Require Epic EHR launch context
        required_scopes: List of required OAuth2 scopes
        
    Returns:
        Decorator function
    """
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                # Get and validate token
                token = get_valid_token(
                    auto_refresh=auto_refresh,
                    require_epic_context=require_epic_context,
                    required_scopes=required_scopes
                )
                
                # Store token in request context
                g.token = token
                g.epic_user_id = token.get('epicUserID')
                
                # Store Epic endpoints if available
                if token.get('getMessage'):
                    g.get_message_url = token['getMessage']
                if token.get('setMessage'):
                    g.set_message_url = token['setMessage']
                
                # Call the original route function with token
                kwargs['token'] = token
                return f(*args, **kwargs)
                
            except TokenRevokedException as e:
                return handle_token_revocation(e)
                
            except (TokenExpiredError, TokenRefreshError) as e:
                return handle_token_expiration(e)
                
            except AuthenticationError as e:
                return handle_authentication_error(e)
                
            except Exception as e:
                logger.error(f"Unexpected error in authentication: {str(e)}")
                return handle_unexpected_auth_error(e)
                
        return decorated_function
    return decorator


def require_epic_launch():
    """
    Decorator specifically for Epic EHR launch context.
    
    Ensures the route was accessed through Epic launch and has appropriate context.
    """
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                # Check for Epic launch context in session
                if not session.get('launch'):
                    log_security_event(
                        'invalid_epic_launch',
                        {'request_path': request.path, 'session_keys': list(session.keys())}
                    )
                    return redirect(url_for('auth.launch_error', 
                                          error='missing_launch_context'))
                
                # Check for Epic ISS (FHIR server URL)
                if not session.get('iss'):
                    log_security_event(
                        'missing_fhir_server',
                        {'request_path': request.path}
                    )
                    return redirect(url_for('auth.launch_error', 
                                          error='missing_fhir_server'))
                
                # Get valid token with Epic context
                token = get_valid_token(
                    auto_refresh=True,
                    require_epic_context=True
                )
                
                # Store Epic context in g
                g.token = token
                g.epic_launch = session.get('launch')
                g.fhir_server = session.get('iss')
                g.epic_user_id = token.get('epicUserID')
                
                # Store Epic endpoints
                g.get_message_url = token.get('getMessage') or session.get('get_message_url')
                g.set_message_url = token.get('setMessage') or session.get('set_message_url')
                
                kwargs['token'] = token
                return f(*args, **kwargs)
                
            except Exception as e:
                logger.error(f"Epic launch validation failed: {str(e)}")
                return redirect(url_for('auth.launch_error', error='validation_failed'))
                
        return decorated_function
    return decorator


def optional_authentication():
    """
    Decorator for routes that work with or without authentication.
    
    Provides token if available but doesn't require it.
    """
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated_function(*args, **kwargs):
            token = None
            
            try:
                # Try to get token but don't fail if not available
                token = get_valid_token(auto_refresh=True, fail_on_missing=False)
                
                if token:
                    g.token = token
                    g.epic_user_id = token.get('epicUserID')
                    kwargs['token'] = token
                else:
                    g.token = None
                    g.epic_user_id = None
                    kwargs['token'] = None
                    
            except Exception as e:
                logger.debug(f"Optional authentication failed (continuing): {e}")
                g.token = None
                g.epic_user_id = None
                kwargs['token'] = None
            
            return f(*args, **kwargs)
            
        return decorated_function
    return decorator


def get_valid_token(
    auto_refresh: bool = True,
    require_epic_context: bool = False,
    required_scopes: Optional[list] = None,
    fail_on_missing: bool = True
) -> Optional[Dict[str, Any]]:
    """
    Get a valid token from session with optional refresh.
    
    Args:
        auto_refresh: Automatically refresh expired tokens
        require_epic_context: Require Epic EHR context
        required_scopes: List of required OAuth2 scopes
        fail_on_missing: Raise exception if no token found
        
    Returns:
        Valid token dictionary or None
        
    Raises:
        AuthenticationError: If authentication fails
        TokenRevokedException: If token is revoked
        TokenExpiredError: If token is expired and can't be refreshed
    """
    # Get token from session
    token = session.get('token')
    
    if not token:
        if fail_on_missing:
            log_security_event(
                'missing_token',
                {'request_path': request.path if request else None}
            )
            raise AuthenticationError("No authentication token found")
        return None
    
    # Validate Epic context if required
    if require_epic_context:
        if not token.get('need_patient_banner') and not session.get('launch'):
            raise AuthenticationError("Epic EHR launch context required")
        
        epic_user_id = token.get('epicUserID')
        if not epic_user_id:
            raise AuthenticationError("Epic user ID not found in token")
    
    # Validate required scopes
    if required_scopes:
        token_scopes = token.get('scope', '').split()
        missing_scopes = [scope for scope in required_scopes if scope not in token_scopes]
        if missing_scopes:
            raise AuthenticationError(f"Missing required scopes: {missing_scopes}")
    
    # Check if token needs refresh
    token_manager = get_token_manager()
    
    if auto_refresh and token_manager.is_token_expired(token):
        try:
            # Get configuration for refresh
            client_id = get_epic_client_id()
            token_endpoint = get_token_endpoint()
            
            # Attempt refresh
            new_token, was_refreshed = token_manager.refresh_token_if_needed(
                token, client_id, token_endpoint
            )
            
            if was_refreshed:
                # Update session with new token
                session['token'] = new_token
                session.permanent = True
                
                logger.info("Token refreshed successfully")
                return new_token
            else:
                return token
                
        except TokenRevokedException:
            # Clear session and re-raise
            clear_authentication_session()
            raise
            
        except Exception as e:
            logger.error(f"Token refresh failed: {e}")
            if fail_on_missing:
                raise TokenRefreshError(f"Failed to refresh token: {e}")
            return None
    
    # Validate token structure
    try:
        if not token_manager.validate_token(token):
            raise InvalidTokenError("Token validation failed")
    except (InvalidTokenError, TokenExpiredError) as e:
        if fail_on_missing:
            raise
        return None
    
    return token


def handle_token_revocation(error: TokenRevokedException) -> Any:
    """
    Handle token revocation by clearing session and redirecting to auth.
    
    Args:
        error: Token revocation exception
        
    Returns:
        Redirect response to authentication
    """
    logger.warning(f"Token revoked: {error}")
    
    # Log security event
    log_security_event(
        'token_revoked_handled',
        {
            'request_path': request.path if request else None,
            'error_message': str(error)
        }
    )
    
    # Clear authentication session
    clear_authentication_session()
    
    # Set revocation flag for UI feedback
    session['token_revoked'] = True
    
    # Redirect to launch/login
    return redirect(url_for('auth.launch'))


def handle_token_expiration(error: Exception) -> Any:
    """
    Handle token expiration errors.
    
    Args:
        error: Token expiration or refresh error
        
    Returns:
        Redirect response or error page
    """
    logger.warning(f"Token expiration/refresh error: {error}")
    
    # Clear invalid token
    session.pop('token', None)
    
    # Redirect to re-authentication
    return redirect(url_for('auth.launch'))


def handle_authentication_error(error: AuthenticationError) -> Any:
    """
    Handle general authentication errors.
    
    Args:
        error: Authentication error
        
    Returns:
        Redirect response or error page
    """
    logger.warning(f"Authentication error: {error}")
    
    log_security_event(
        'authentication_error',
        {
            'error_type': type(error).__name__,
            'error_message': str(error),
            'request_path': request.path if request else None
        }
    )
    
    # Clear session
    clear_authentication_session()
    
    # Redirect to authentication with error context
    return redirect(url_for('auth.launch', error='authentication_failed'))


def handle_unexpected_auth_error(error: Exception) -> Any:
    """
    Handle unexpected authentication errors.
    
    Args:
        error: Unexpected error
        
    Returns:
        Error response
    """
    logger.error(f"Unexpected authentication error: {error}")
    
    log_security_event(
        'unexpected_auth_error',
        {
            'error_type': type(error).__name__,
            'error_message': str(error),
            'request_path': request.path if request else None
        },
        level='ERROR'
    )
    
    # Clear session to be safe
    clear_authentication_session()
    
    # Return error response
    if request and request.is_json:
        return {'error': 'Authentication system error'}, 500
    else:
        return redirect(url_for('auth.launch', error='system_error'))


def clear_authentication_session() -> None:
    """Clear authentication-related session data."""
    auth_keys = [
        'token', 'oauth_state', 'iss', 'launch', 'metadata',
        'epic_user_id', 'get_message_url', 'set_message_url'
    ]
    
    for key in auth_keys:
        session.pop(key, None)
    
    logger.debug("Authentication session cleared")


def get_epic_client_id() -> str:
    """
    Get Epic client ID from secrets.
    
    Returns:
        Epic client ID
        
    Raises:
        AuthenticationError: If client ID cannot be retrieved
    """
    try:
        secret_manager = get_secret_manager()
        client_id_secret = current_app.config.get('EPIC_CLIENT_ID_SECRET')
        
        if not client_id_secret:
            raise AuthenticationError("EPIC_CLIENT_ID_SECRET not configured")
        
        return secret_manager.get_secret(client_id_secret)
        
    except Exception as e:
        logger.error(f"Failed to get Epic client ID: {e}")
        raise AuthenticationError(f"Failed to retrieve client credentials: {e}")


def get_token_endpoint() -> str:
    """
    Get token endpoint from session metadata.
    
    Returns:
        Token endpoint URL
        
    Raises:
        AuthenticationError: If token endpoint not available
    """
    metadata = session.get('metadata')
    if not metadata:
        raise AuthenticationError("OAuth metadata not found in session")
    
    token_endpoint = metadata.get('token')
    if not token_endpoint:
        raise AuthenticationError("Token endpoint not found in metadata")
    
    return token_endpoint


def check_session_timeout() -> bool:
    """
    Check if session has timed out based on configuration.
    
    Returns:
        True if session is valid, False if timed out
    """
    try:
        session_timeout = current_app.config.get('SESSION_TIMEOUT_HOURS', 8)
        token = session.get('token')
        
        if not token or 'created_at' not in token:
            return False
        
        created_at_str = token['created_at']
        from datetime import datetime, timezone, timedelta
        
        if isinstance(created_at_str, str):
            created_at = datetime.fromisoformat(created_at_str.replace('Z', '+00:00'))
        else:
            created_at = created_at_str
        
        timeout_at = created_at + timedelta(hours=session_timeout)
        
        return datetime.now(timezone.utc) < timeout_at
        
    except Exception as e:
        logger.warning(f"Session timeout check failed: {e}")
        return False


def require_session_timeout_check():
    """
    Decorator to check session timeout before route execution.
    """
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not check_session_timeout():
                logger.info("Session timed out")
                clear_authentication_session()
                session['session_timeout'] = True
                return redirect(url_for('auth.launch'))
            
            return f(*args, **kwargs)
            
        return decorated_function
    return decorator


def get_current_user_info() -> Dict[str, Any]:
    """
    Get current user information from token and session.
    
    Returns:
        Dictionary with current user info
    """
    user_info = {
        'authenticated': False,
        'epic_user_id': None,
        'scopes': [],
        'token_expires_at': None,
        'epic_endpoints': {}
    }
    
    try:
        token = session.get('token')
        if not token:
            return user_info
        
        user_info.update({
            'authenticated': True,
            'epic_user_id': token.get('epicUserID'),
            'scopes': token.get('scope', '').split(),
            'token_expires_at': token.get('expires_at'),
            'epic_endpoints': {
                'getMessage': token.get('getMessage'),
                'setMessage': token.get('setMessage')
            }
        })
        
        # Add session context
        user_info['session_context'] = {
            'iss': session.get('iss'),
            'launch': session.get('launch'),
            'epic_user_id': session.get('epic_user_id')
        }
        
    except Exception as e:
        logger.warning(f"Error getting user info: {e}")
    
    return user_info


def is_user_authenticated() -> bool:
    """
    Check if user is currently authenticated.
    
    Returns:
        True if authenticated with valid token
    """
    try:
        token = get_valid_token(auto_refresh=False, fail_on_missing=False)
        return token is not None
    except:
        return False


def require_scope(*required_scopes: str):
    """
    Decorator to require specific OAuth2 scopes.
    
    Args:
        required_scopes: OAuth2 scopes that are required
    """
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated_function(*args, **kwargs):
            token = session.get('token')
            if not token:
                raise AuthenticationError("No authentication token found")
            
            token_scopes = token.get('scope', '').split()
            missing_scopes = [scope for scope in required_scopes if scope not in token_scopes]
            
            if missing_scopes:
                log_security_event(
                    'insufficient_scopes',
                    {
                        'required_scopes': list(required_scopes),
                        'token_scopes': token_scopes,
                        'missing_scopes': missing_scopes,
                        'request_path': request.path if request else None
                    }
                )
                raise AuthenticationError(f"Insufficient permissions. Missing scopes: {missing_scopes}")
            
            return f(*args, **kwargs)
            
        return decorated_function
    return decorator


def require_epic_endpoint(endpoint_type: str):
    """
    Decorator to require specific Epic endpoints (getMessage, setMessage).
    
    Args:
        endpoint_type: Type of endpoint required ('getMessage' or 'setMessage')
    """
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated_function(*args, **kwargs):
            token = session.get('token')
            if not token:
                raise AuthenticationError("No authentication token found")
            
            endpoint_url = token.get(endpoint_type) or session.get(f'{endpoint_type.lower()}_url')
            
            if not endpoint_url:
                raise AuthenticationError(f"Epic {endpoint_type} endpoint not available. "
                                        "Ensure application was launched from Epic with bidirectional coding enabled.")
            
            # Store endpoint in request context
            setattr(g, f'{endpoint_type.lower()}_url', endpoint_url)
            
            return f(*args, **kwargs)
            
        return decorated_function
    return decorator