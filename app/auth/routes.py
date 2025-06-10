"""
Authentication routes for Epic HL7 Integration application.

Streamlined for HL7 workflow focus - removed FHIR-specific functionality.
This module provides OAuth2 authentication endpoints including Epic EHR launch,
callback handling, token management, and JWKS distribution.

Routes:
- GET /launch - Epic EHR launch endpoint
- GET /callback - OAuth2 callback handler
- GET /.well-known/jwks.json - JWKS public key distribution
- GET /auth/error - Authentication error handler
- POST /auth/logout - User logout
- GET /auth/status - Authentication status check

Testing/Debug Routes (development only):
- GET /auth/debug/token - Token information
- POST /auth/debug/refresh - Force token refresh
- POST /auth/debug/revoke - Revoke token
- POST /auth/debug/expire - Force token expiration
"""

import secrets
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from flask import Blueprint, request, session, redirect, url_for, jsonify, render_template, current_app, g
from requests_oauthlib import OAuth2Session
import requests

from app.core.exceptions import (
    AuthenticationError, TokenError, TokenRevokedException, 
    ConfigurationError, handle_requests_error
)
from app.core.logging import get_logger, log_security_event, log_epic_event, log_performance
from app.core.secrets import get_secret_manager
from app.auth.token_manager import get_token_manager, create_client_assertion, load_jwks
from app.auth.decorators import require_valid_token, optional_authentication, get_current_user_info


logger = get_logger(__name__)


def create_auth_blueprint() -> Blueprint:
    """
    Create and configure the authentication blueprint.
    
    Returns:
        Configured Flask blueprint for authentication routes
    """
    bp = Blueprint('auth', __name__)
    
    # Register route handlers
    bp.add_url_rule('/launch', 'launch', launch, methods=['GET'])
    bp.add_url_rule('/callback', 'callback', callback, methods=['GET'])
    bp.add_url_rule('/epic-sandbox/callback', 'epic_callback', callback, methods=['GET'])  # Legacy support
    bp.add_url_rule('/.well-known/jwks.json', 'jwks', jwks_endpoint, methods=['GET'])
    bp.add_url_rule('/auth/error', 'error', auth_error, methods=['GET'])
    bp.add_url_rule('/auth/logout', 'logout', logout, methods=['POST'])
    bp.add_url_rule('/auth/status', 'status', auth_status, methods=['GET'])
    
    # Development/testing routes
    if current_app and current_app.config.get('FLASK_ENV') == 'development':
        bp.add_url_rule('/auth/debug/token', 'debug_token', debug_token_info, methods=['GET'])
        bp.add_url_rule('/auth/debug/refresh', 'debug_refresh', debug_refresh_token, methods=['POST'])
        bp.add_url_rule('/auth/debug/revoke', 'debug_revoke', debug_revoke_token, methods=['POST'])
        bp.add_url_rule('/auth/debug/expire', 'debug_expire', debug_expire_token, methods=['POST'])
    
    logger.info("Authentication blueprint created for HL7 integration")
    return bp


def launch():
    """
    Handle Epic EHR launch request for HL7 messaging.
    
    This endpoint initiates the OAuth2 authorization flow with Epic.
    Supports both EHR launch (with launch parameter) and standalone launch.
    
    Query Parameters:
        iss (str): FHIR server base URL from Epic
        launch (str, optional): Launch token for EHR launch context
        
    Returns:
        Redirect to Epic authorization endpoint or error page
    """
    try:
        with log_performance("epic_launch_initiation", logger):
            # Clear any existing authentication state
            clear_auth_session()
            
            # Get launch parameters
            iss = request.args.get('iss')
            launch_token = request.args.get('launch')
            
            # Log launch attempt
            log_epic_event(
                'hl7_launch_initiated',
                {
                    'iss': iss,
                    'has_launch_token': bool(launch_token),
                    'user_agent': request.headers.get('User-Agent'),
                    'remote_addr': request.remote_addr
                }
            )
            
            # Validate launch parameters
            if not iss:
                logger.warning("Launch attempt missing ISS parameter")
                return redirect(url_for('auth.error', error='missing_iss'))
            
            if not iss.startswith(('http://', 'https://')):
                logger.warning(f"Invalid ISS format: {iss}")
                return redirect(url_for('auth.error', error='invalid_iss'))
            
            # Store launch context in session
            session['iss'] = iss
            if launch_token:
                session['launch'] = launch_token
                session['launch_type'] = 'ehr_launch'
            else:
                session['launch_type'] = 'standalone_launch'
            
            # Get Epic metadata for OAuth endpoints
            logger.info(f"Fetching Epic metadata from: {iss}")
            
            try:
                from app.fhir.metadata import get_epic_metadata
                metadata = get_epic_metadata(iss)
                auth_endpoints = metadata.auth_endpoints
                
                if not auth_endpoints.get('authorize') or not auth_endpoints.get('token'):
                    raise ConfigurationError("Epic metadata missing required OAuth endpoints")
                
                session['metadata'] = auth_endpoints
                
                log_epic_event(
                    'metadata_retrieved',
                    {
                        'iss': iss,
                        'authorize_endpoint': auth_endpoints.get('authorize'),
                        'token_endpoint': auth_endpoints.get('token')
                    }
                )
                
            except Exception as e:
                logger.error(f"Failed to retrieve Epic metadata: {e}")
                return redirect(url_for('auth.error', error='metadata_failure', details=str(e)))
            
            # Get Epic client credentials
            try:
                secret_manager = get_secret_manager()
                client_id_secret = current_app.config.get('EPIC_CLIENT_ID_SECRET')
                
                if not client_id_secret:
                    raise ConfigurationError("EPIC_CLIENT_ID_SECRET not configured")
                
                epic_client_id = secret_manager.get_secret(client_id_secret)
                
            except Exception as e:
                logger.error(f"Failed to retrieve Epic client credentials: {e}")
                return redirect(url_for('auth.error', error='credentials_failure'))
            
            # Generate OAuth state parameter for CSRF protection
            oauth_state = secrets.token_hex(32)
            session['oauth_state'] = oauth_state
            
            # Determine OAuth scopes for HL7 integration
            if launch_token:
                # EHR launch scopes - optimized for HL7 messaging
                scopes = ['openid', 'fhirUser', 'launch']
            else:
                # Standalone launch scopes - minimal for HL7 testing
                scopes = ['openid', 'fhirUser']
            
            session['requested_scopes'] = scopes
            
            # Initialize OAuth2 session
            oauth2_session = OAuth2Session(
                epic_client_id,
                redirect_uri=url_for('auth.callback', _external=True),
                scope=' '.join(scopes),
                state=oauth_state
            )
            
            # Build authorization URL
            auth_params = {
                'aud': iss  # Audience parameter required by Epic
            }
            
            if launch_token:
                auth_params['launch'] = launch_token
            
            authorization_url, returned_state = oauth2_session.authorization_url(
                auth_endpoints['authorize'],
                **auth_params
            )
            
            # Verify state consistency
            if returned_state != oauth_state:
                logger.error("OAuth state mismatch during authorization URL generation")
                return redirect(url_for('auth.error', error='state_mismatch'))
            
            # Log successful launch initiation
            log_security_event(
                'oauth_hl7_launch_initiated',
                {
                    'client_id': epic_client_id,
                    'iss': iss,
                    'scopes': scopes,
                    'launch_type': session['launch_type']
                }
            )
            
            logger.info(
                f"Redirecting to Epic authorization for HL7 integration",
                extra={
                    'authorization_url': authorization_url.split('?')[0],
                    'client_id': epic_client_id,
                    'scopes': scopes
                }
            )
            
            return redirect(authorization_url)
            
    except Exception as e:
        logger.error(f"Unexpected error during HL7 launch: {e}", exc_info=True)
        log_security_event(
            'hl7_launch_error',
            {'error': str(e), 'error_type': type(e).__name__},
            level='ERROR'
        )
        return redirect(url_for('auth.error', error='unexpected_error'))


def callback():
    """
    Handle OAuth2 callback from Epic for HL7 integration.
    
    This endpoint receives the authorization code from Epic and exchanges it
    for access and refresh tokens. Handles both successful authorization and
    error responses.
    
    Query Parameters:
        code (str): Authorization code from Epic
        state (str): OAuth state parameter for CSRF protection
        error (str, optional): Error code if authorization failed
        error_description (str, optional): Human-readable error description
        
    Returns:
        Redirect to HL7 menu or error page
    """
    try:
        with log_performance("oauth_callback_processing", logger):
            # Check for OAuth errors first
            oauth_error = request.args.get('error')
            if oauth_error:
                error_description = request.args.get('error_description', 'No description provided')
                
                logger.warning(
                    f"OAuth authorization failed: {oauth_error}",
                    extra={
                        'error': oauth_error,
                        'error_description': error_description
                    }
                )
                
                log_security_event(
                    'oauth_authorization_denied',
                    {
                        'error': oauth_error,
                        'error_description': error_description
                    }
                )
                
                return redirect(url_for('auth.error', error='oauth_denied', details=oauth_error))
            
            # Validate required session data
            if not session.get('oauth_state'):
                logger.error("Missing OAuth state in session during callback")
                return redirect(url_for('auth.error', error='missing_session_state'))
            
            if not session.get('metadata'):
                logger.error("Missing OAuth metadata in session during callback")
                return redirect(url_for('auth.error', error='missing_metadata'))
            
            # Validate state parameter
            returned_state = request.args.get('state')
            expected_state = session.get('oauth_state')
            
            if not returned_state or returned_state != expected_state:
                logger.error(
                    f"OAuth state mismatch: expected {expected_state}, got {returned_state}"
                )
                log_security_event(
                    'oauth_state_mismatch',
                    {
                        'expected_state': expected_state,
                        'returned_state': returned_state
                    },
                    level='ERROR'
                )
                return redirect(url_for('auth.error', error='state_mismatch'))
            
            # Get authorization code
            auth_code = request.args.get('code')
            if not auth_code:
                logger.error("Missing authorization code in callback")
                return redirect(url_for('auth.error', error='missing_auth_code'))
            
            # Get client credentials
            try:
                secret_manager = get_secret_manager()
                client_id_secret = current_app.config.get('EPIC_CLIENT_ID_SECRET')
                epic_client_id = secret_manager.get_secret(client_id_secret)
                
            except Exception as e:
                logger.error(f"Failed to retrieve client credentials during callback: {e}")
                return redirect(url_for('auth.error', error='credentials_failure'))
            
            # Exchange authorization code for tokens
            logger.info("Exchanging authorization code for HL7 access token")
            
            try:
                token = exchange_code_for_token(
                    auth_code=auth_code,
                    client_id=epic_client_id,
                    token_endpoint=session['metadata']['token'],
                    redirect_uri=url_for('auth.callback', _external=True)
                )
                
            except Exception as e:
                logger.error(f"Token exchange failed: {e}")
                return redirect(url_for('auth.error', error='token_exchange_failed', details=str(e)))
            
            # Validate and store token
            try:
                token_manager = get_token_manager()
                
                if not token_manager.validate_token(token):
                    raise TokenError("Received invalid token from Epic")
                
                # Add metadata to token
                token['created_at'] = datetime.now(timezone.utc).isoformat()
                token['client_id'] = epic_client_id
                token['iss'] = session.get('iss')
                token['launch_type'] = session.get('launch_type')
                
                # Store token in session
                session['token'] = token
                session.permanent = True  # Make session persistent
                
                # Store Epic-specific context
                epic_user_id = token.get('epicUserID')
                if epic_user_id:
                    session['epic_user_id'] = epic_user_id
                
                # Store Epic HL7 endpoints for bidirectional coding
                if token.get('getMessage'):
                    session['get_message_url'] = token['getMessage']
                if token.get('setMessage'):
                    session['set_message_url'] = token['setMessage']
                
                # Log successful authentication
                log_security_event(
                    'oauth_hl7_authentication_success',
                    {
                        'client_id': epic_client_id,
                        'epic_user_id': epic_user_id,
                        'scopes': token.get('scope', '').split(),
                        'has_refresh_token': 'refresh_token' in token,
                        'launch_type': session.get('launch_type'),
                        'hl7_endpoints_available': bool(token.get('getMessage') or token.get('setMessage'))
                    }
                )
                
                log_epic_event(
                    'hl7_authentication_completed',
                    {
                        'epic_user_id': epic_user_id,
                        'token_expires_in': token.get('expires_in'),
                        'scopes': token.get('scope'),
                        'hl7_endpoints': {
                            'getMessage': token.get('getMessage'),
                            'setMessage': token.get('setMessage')
                        }
                    }
                )
                
                logger.info(
                    "OAuth authentication completed for HL7 integration",
                    extra={
                        'epic_user_id': epic_user_id,
                        'scopes': token.get('scope', '').split(),
                        'launch_type': session.get('launch_type'),
                        'hl7_endpoints': bool(token.get('getMessage') or token.get('setMessage'))
                    }
                )
                
                # Clear OAuth-specific session data
                for key in ['oauth_state', 'requested_scopes']:
                    session.pop(key, None)
                
                # Redirect to HL7 workflow menu
                return redirect(url_for('web.menu'))
                
            except Exception as e:
                logger.error(f"Token validation/storage failed: {e}")
                return redirect(url_for('auth.error', error='token_validation_failed'))
            
    except Exception as e:
        logger.error(f"Unexpected error during HL7 callback: {e}", exc_info=True)
        log_security_event(
            'hl7_callback_error',
            {'error': str(e), 'error_type': type(e).__name__},
            level='ERROR'
        )
        return redirect(url_for('auth.error', error='unexpected_error'))


def jwks_endpoint():
    """
    JWKS (JSON Web Key Set) endpoint for OAuth2 public key distribution.
    
    Provides public keys used to verify JWT signatures for client assertions.
    This endpoint is typically called by Epic to verify our client assertions.
    
    Returns:
        JSON response containing public keys in JWKS format
    """
    try:
        with log_performance("jwks_generation", logger):
            jwks_data = load_jwks()
            
            logger.debug("JWKS endpoint accessed successfully")
            
            # Add CORS headers for cross-origin requests
            response = jsonify(jwks_data)
            response.headers['Access-Control-Allow-Origin'] = '*'
            response.headers['Cache-Control'] = 'public, max-age=3600'  # Cache for 1 hour
            
            return response
            
    except Exception as e:
        logger.error(f"Failed to generate JWKS: {e}")
        return jsonify({'error': 'Failed to load JWKS'}), 500


def auth_error():
    """
    Authentication error handler for HL7 integration.
    
    Displays user-friendly error messages for authentication failures.
    
    Query Parameters:
        error (str): Error code
        details (str, optional): Additional error details
        
    Returns:
        Rendered error template or JSON error response
    """
    error_code = request.args.get('error', 'unknown_error')
    error_details = request.args.get('details', '')
    
    # Define user-friendly error messages for HL7 integration
    error_messages = {
        'missing_iss': {
            'title': 'Missing Epic Server',
            'message': 'No Epic server URL provided. Please launch from Epic EHR with HL7 coding interface enabled.',
            'action': 'Contact your Epic administrator to enable bidirectional coding for this application.'
        },
        'invalid_iss': {
            'title': 'Invalid Epic Server URL',
            'message': 'The provided Epic server URL is not valid.',
            'action': 'Verify the URL format and try launching from Epic again.'
        },
        'metadata_failure': {
            'title': 'Epic Configuration Error',
            'message': 'Unable to retrieve Epic server configuration for HL7 integration.',
            'action': 'Check network connectivity and Epic server availability.'
        },
        'credentials_failure': {
            'title': 'Authentication Configuration Error',
            'message': 'Unable to retrieve Epic authentication credentials.',
            'action': 'Contact system administrator to verify Epic client configuration.'
        },
        'state_mismatch': {
            'title': 'Security Validation Failed',
            'message': 'Authentication request validation failed.',
            'action': 'Please try launching from Epic again.'
        },
        'oauth_denied': {
            'title': 'Epic Authorization Denied',
            'message': 'Epic authorization was denied or cancelled.',
            'action': 'Please try again and approve the authorization request in Epic.'
        },
        'token_exchange_failed': {
            'title': 'Token Exchange Failed',
            'message': 'Failed to obtain access token from Epic for HL7 integration.',
            'action': 'Please try authenticating again from Epic EHR.'
        },
        'unexpected_error': {
            'title': 'Unexpected Error',
            'message': 'An unexpected error occurred during Epic HL7 authentication.',
            'action': 'Please try again or contact support if the problem persists.'
        }
    }
    
    error_info = error_messages.get(error_code, {
        'title': 'HL7 Authentication Error',
        'message': f'HL7 authentication failed with error: {error_code}',
        'action': 'Please try launching from Epic EHR again or contact support.'
    })
    
    # Add details if provided
    if error_details:
        error_info['details'] = error_details
    
    # Log the error for monitoring
    log_security_event(
        'hl7_auth_error_displayed',
        {
            'error_code': error_code,
            'error_details': error_details,
            'user_agent': request.headers.get('User-Agent')
        }
    )
    
    logger.warning(f"HL7 authentication error displayed: {error_code}", extra={'details': error_details})
    
    # Return JSON for API requests, HTML for browser requests
    if request.is_json or request.args.get('format') == 'json':
        return jsonify({
            'error': error_code,
            'error_info': error_info
        }), 400
    
    return render_template('auth/error.html', error_info=error_info), 400


@optional_authentication()
def auth_status(token: Optional[Dict[str, Any]] = None):
    """
    Get current authentication status for HL7 integration.
    
    Provides information about the current authentication state,
    token status, and HL7 endpoint availability.
    
    Returns:
        JSON response with authentication status
    """
    try:
        if token:
            token_manager = get_token_manager()
            token_info = token_manager.get_token_info(token)
            
            user_info = get_current_user_info()
            
            status = {
                'authenticated': True,
                'user_info': user_info,
                'token_info': {
                    'is_valid': token_info.get('is_valid'),
                    'expires_in_minutes': token_info.get('expires_in_minutes'),
                    'scopes': token_info.get('scope', '').split() if token_info.get('scope') else [],
                    'has_refresh_token': token_info.get('has_refresh_token'),
                    'hl7_endpoints': {
                        'getMessage': bool(session.get('get_message_url')),
                        'setMessage': bool(session.get('set_message_url'))
                    }
                },
                'session_info': {
                    'launch_type': session.get('launch_type'),
                    'iss': session.get('iss'),
                    'epic_user_id': session.get('epic_user_id')
                }
            }
        else:
            status = {
                'authenticated': False,
                'message': 'No valid authentication token found'
            }
        
        return jsonify(status)
        
    except Exception as e:
        logger.error(f"Error getting HL7 auth status: {e}")
        return jsonify({
            'authenticated': False,
            'error': 'Failed to determine authentication status'
        }), 500


def logout():
    """
    Log out the current user from HL7 integration.
    
    Clears session data and optionally revokes tokens.
    
    Returns:
        JSON response indicating logout status
    """
    try:
        # Get current token for optional revocation
        token = session.get('token')
        epic_user_id = session.get('epic_user_id')
        
        # Clear all session data
        clear_auth_session()
        
        # Log logout event
        log_security_event(
            'hl7_user_logout',
            {
                'epic_user_id': epic_user_id,
                'had_token': bool(token)
            }
        )
        
        logger.info(f"HL7 user logged out", extra={'epic_user_id': epic_user_id})
        
        return jsonify({
            'status': 'success',
            'message': 'Logged out successfully from HL7 integration'
        })
        
    except Exception as e:
        logger.error(f"Error during HL7 logout: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Logout failed'
        }), 500


# Development/Testing Routes
@require_valid_token
def debug_token_info(token: Dict[str, Any]):
    """Debug endpoint to display detailed token information for HL7 integration."""
    try:
        token_manager = get_token_manager()
        token_info = token_manager.get_token_info(token)
        
        # Add HL7-specific session context
        session_context = {
            'iss': session.get('iss'),
            'launch': session.get('launch'),
            'launch_type': session.get('launch_type'),
            'epic_user_id': session.get('epic_user_id'),
            'hl7_endpoints': {
                'get_message_url': session.get('get_message_url'),
                'set_message_url': session.get('set_message_url')
            },
            'metadata': session.get('metadata')
        }
        
        debug_info = {
            'token_info': token_info,
            'session_context': session_context,
            'request_context': {
                'remote_addr': request.remote_addr,
                'user_agent': request.headers.get('User-Agent'),
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
        }
        
        return jsonify(debug_info)
        
    except Exception as e:
        logger.error(f"Error in HL7 debug token info: {e}")
        return jsonify({'error': str(e)}), 500


def debug_refresh_token():
    """Debug endpoint to force token refresh for HL7 integration."""
    try:
        token = session.get('token')
        if not token:
            return jsonify({'error': 'No token found in session'}), 400
        
        # Get required components for refresh
        secret_manager = get_secret_manager()
        client_id_secret = current_app.config.get('EPIC_CLIENT_ID_SECRET')
        epic_client_id = secret_manager.get_secret(client_id_secret)
        token_endpoint = session.get('metadata', {}).get('token')
        
        if not token_endpoint:
            return jsonify({'error': 'No token endpoint found in session'}), 400
        
        # Force refresh
        token_manager = get_token_manager()
        new_token, was_refreshed = token_manager.refresh_token_if_needed(
            token, epic_client_id, token_endpoint, force_refresh=True
        )
        
        if was_refreshed:
            session['token'] = new_token
            
            return jsonify({
                'status': 'success',
                'message': 'HL7 token refreshed successfully',
                'old_expires_at': token.get('expires_at'),
                'new_expires_at': new_token.get('expires_at')
            })
        else:
            return jsonify({
                'status': 'no_refresh_needed',
                'message': 'HL7 token did not need refresh'
            })
            
    except Exception as e:
        logger.error(f"Error in HL7 debug refresh: {e}")
        return jsonify({'error': str(e)}), 500


def debug_revoke_token():
    """Debug endpoint to simulate token revocation for HL7 integration."""
    try:
        epic_user_id = session.get('epic_user_id')
        
        # Clear token but keep other session data for testing
        session.pop('token', None)
        session['token_revoked'] = True
        
        log_security_event(
            'hl7_debug_token_revoked',
            {'epic_user_id': epic_user_id}
        )
        
        return jsonify({
            'status': 'success',
            'message': 'HL7 token revoked (simulation)',
            'next_action': 'Try accessing a protected HL7 endpoint to test revocation handling'
        })
        
    except Exception as e:
        logger.error(f"Error in HL7 debug revoke: {e}")
        return jsonify({'error': str(e)}), 500


def debug_expire_token():
    """Debug endpoint to force token expiration for HL7 integration."""
    try:
        token = session.get('token')
        if not token:
            return jsonify({'error': 'No token found in session'}), 400
        
        # Force token to be expired
        from datetime import timedelta
        old_time = datetime.now(timezone.utc) - timedelta(hours=1)
        
        token['created_at'] = old_time.isoformat()
        token['expires_at'] = old_time.timestamp()
        
        session['token'] = token
        
        return jsonify({
            'status': 'success',
            'message': 'HL7 token expiration forced',
            'expires_at': token['expires_at'],
            'next_action': 'Try accessing a protected HL7 endpoint to test refresh logic'
        })
        
    except Exception as e:
        logger.error(f"Error in HL7 debug expire: {e}")
        return jsonify({'error': str(e)}), 500


# Helper Functions
def exchange_code_for_token(
    auth_code: str, 
    client_id: str, 
    token_endpoint: str, 
    redirect_uri: str
) -> Dict[str, Any]:
    """
    Exchange authorization code for access token.
    
    Args:
        auth_code: Authorization code from Epic
        client_id: OAuth client ID
        token_endpoint: Token endpoint URL
        redirect_uri: Redirect URI used in authorization
        
    Returns:
        Token dictionary from Epic
        
    Raises:
        TokenError: If token exchange fails
    """
    try:
        # Create client assertion for authentication
        client_assertion = create_client_assertion(client_id, token_endpoint)
        
        # Prepare token request
        token_params = {
            'grant_type': 'authorization_code',
            'code': auth_code,
            'redirect_uri': redirect_uri,
            'client_id': client_id,
            'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion': client_assertion
        }
        
        # Make token request
        response = requests.post(
            token_endpoint,
            data=token_params,
            headers={
                'Content-Type': 'application/x-www-form-urlencoded',
                'Accept': 'application/json'
            },
            timeout=30
        )
        
        # Handle response
        if not response.ok:
            error_detail = "Unknown error"
            try:
                error_body = response.json()
                error_detail = error_body.get('error_description', error_body.get('error', str(error_body)))
            except:
                error_detail = response.text
            
            raise TokenError(f"Token exchange failed: {error_detail}")
        
        token = response.json()
        
        # Validate token response
        if 'access_token' not in token:
            raise TokenError("Token response missing access_token")
        
        logger.info("Token exchange completed successfully for HL7 integration")
        return token
        
    except requests.RequestException as e:
        raise TokenError(f"Network error during token exchange: {str(e)}")
    except Exception as e:
        raise TokenError(f"Token exchange failed: {str(e)}")


def clear_auth_session():
    """Clear all authentication-related session data."""
    auth_keys = [
        'token', 'oauth_state', 'iss', 'launch', 'metadata',
        'epic_user_id', 'get_message_url', 'set_message_url',
        'launch_type', 'requested_scopes', 'token_revoked'
    ]
    
    for key in auth_keys:
        session.pop(key, None)
    
    logger.debug("HL7 authentication session data cleared")


def init_auth_logging():
    """Initialize authentication-specific logging configuration."""
    auth_logger = get_logger('epic_hl7.auth')
    auth_logger.info("HL7 authentication module logging initialized")


# Initialize logging when module is imported
init_auth_logging()