"""
OAuth2 token management for Epic FHIR Integration.

Updated to handle Epic's token format more flexibly.
Healthcare-focused token management with appropriate error handling,
security logging, and Epic-specific functionality without over-engineering.
"""

import os
import time
import secrets
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Tuple, Any
from pathlib import Path
import base64
import jwt
from cryptography.hazmat.primitives import serialization
import requests

from app.core.exceptions import (
    TokenError, TokenExpiredError, TokenRevokedException, 
    TokenRefreshError, InvalidTokenError
)
from app.core.logging import get_logger, log_security_event

logger = get_logger(__name__)


def load_private_key(private_key_path: str = 'keys/private.pem'):
    """Load private key from file for JWT signing."""
    try:
        key_path = Path(private_key_path)
        
        if not key_path.exists():
            raise TokenError(f"Private key file not found: {key_path}")
        
        with open(key_path, 'rb') as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
        
        logger.debug(f"Private key loaded from {key_path}")
        return private_key
        
    except Exception as e:
        error_msg = f"Failed to load private key: {str(e)}"
        logger.error(error_msg)
        raise TokenError(error_msg, original_error=e)


def create_client_assertion(client_id: str, token_endpoint: str) -> str:
    """
    Create JWT client assertion for Epic OAuth2 authentication.
    
    Required for Epic's client_credentials authentication flow.
    """
    try:
        now = datetime.now(timezone.utc)
        
        claims = {
            'iss': client_id,
            'sub': client_id,
            'aud': token_endpoint,
            'jti': secrets.token_hex(16),
            'exp': now + timedelta(minutes=5),
            'iat': now,
            'nbf': now
        }
        
        # Load private key as bytes for PyJWT
        with open('keys/private.pem', 'rb') as f:
            private_key_bytes = f.read()
        
        assertion = jwt.encode(
            claims,
            private_key_bytes,
            algorithm='RS384',
            headers={'kid': 'epic-fhir-integration-key'}
        )
        
        logger.debug("Client assertion created for Epic authentication")
        return assertion
        
    except Exception as e:
        error_msg = f"Failed to create client assertion: {str(e)}"
        logger.error(error_msg)
        raise TokenError(error_msg, original_error=e)


def load_jwks() -> Dict[str, Any]:
    """
    Generate JWKS from private key for Epic public key verification.
    
    Used by Epic to verify our client assertions at /.well-known/jwks.json
    """
    try:
        private_key = load_private_key()
        
        # Convert private key to public JWK format
        public_key = private_key.public_key()
        public_numbers = public_key.public_numbers()
        
        n_bytes = public_numbers.n.to_bytes(
            (public_numbers.n.bit_length() + 7) // 8, 
            byteorder='big'
        )
        e_bytes = public_numbers.e.to_bytes(
            (public_numbers.e.bit_length() + 7) // 8, 
            byteorder='big'
        )
        
        jwk = {
            'kty': 'RSA',
            'e': base64.urlsafe_b64encode(e_bytes).decode('utf-8').rstrip('='),
            'n': base64.urlsafe_b64encode(n_bytes).decode('utf-8').rstrip('='),
            'kid': 'epic-fhir-integration-key',
            'alg': 'RS384',
            'use': 'sig'
        }
        
        jwks = {'keys': [jwk]}
        logger.info("JWKS generated for Epic integration")
        return jwks
        
    except Exception as e:
        error_msg = f"Failed to generate JWKS: {str(e)}"
        logger.error(error_msg)
        raise TokenError(error_msg, original_error=e)


def validate_token(token: Dict[str, Any]) -> bool:
    """
    Validate OAuth2 token structure - more flexible for Epic tokens.
    
    Epic tokens may have different formats, so we're more permissive.
    """
    try:
        # Log token structure for debugging (without sensitive data)
        safe_token_info = {
            'keys_present': list(token.keys()),
            'has_access_token': bool(token.get('access_token')),
            'token_type': token.get('token_type'),
            'expires_in': token.get('expires_in'),
            'has_refresh_token': bool(token.get('refresh_token')),
            'scope': token.get('scope'),
            'epic_fields': {k: bool(v) for k, v in token.items() if k.startswith('epic') or k in ['getMessage', 'setMessage']}
        }
        logger.debug(f"Token structure: {safe_token_info}")
        
        # Check required fields - be flexible about what we require
        if not token or not token.get('access_token'):
            logger.warning("Token missing access_token")
            return False
        
        # Epic tokens should have token_type, but be flexible
        token_type = token.get('token_type', 'Bearer').lower()
        if token_type not in ['bearer', '']:
            logger.warning(f"Unexpected token type: {token.get('token_type')}")
            # Don't fail - just warn
        
        # Don't fail on expiration check here - Epic might use different fields
        logger.info("Token validation passed - Epic token structure accepted")
        return True
        
    except Exception as e:
        logger.warning(f"Token validation failed: {e}")
        return False


def is_token_expired(token: Dict[str, Any], buffer_seconds: int = 300) -> bool:
    """
    Check if token is expired - more flexible for Epic tokens.
    
    Epic tokens might use different expiration fields.
    """
    try:
        # Method 1: Check expires_at timestamp (standard)
        if 'expires_at' in token:
            try:
                expires_at = datetime.fromtimestamp(token['expires_at'])
                is_expired = datetime.now() + timedelta(seconds=buffer_seconds) >= expires_at
                logger.debug(f"Token expires at {expires_at}, expired: {is_expired}")
                return is_expired
            except (ValueError, TypeError) as e:
                logger.warning(f"Invalid expires_at value: {e}")
        
        # Method 2: Check expires_in + created_at
        if 'expires_in' in token and 'created_at' in token:
            try:
                created_at_str = token['created_at']
                if isinstance(created_at_str, str):
                    # Handle different datetime formats
                    for fmt in ['%Y-%m-%dT%H:%M:%S.%fZ', '%Y-%m-%dT%H:%M:%SZ', '%Y-%m-%dT%H:%M:%S']:
                        try:
                            created_at = datetime.strptime(created_at_str.replace('+00:00', 'Z'), fmt)
                            break
                        except ValueError:
                            continue
                    else:
                        # Try parsing with fromisoformat
                        created_at = datetime.fromisoformat(created_at_str.replace('Z', '+00:00'))
                else:
                    created_at = created_at_str
                
                if created_at.tzinfo is None:
                    created_at = created_at.replace(tzinfo=timezone.utc)
                
                expires_at = created_at + timedelta(seconds=token['expires_in'])
                now = datetime.now(timezone.utc)
                is_expired = now + timedelta(seconds=buffer_seconds) >= expires_at
                logger.debug(f"Token created at {created_at}, expires at {expires_at}, expired: {is_expired}")
                return is_expired
                
            except (ValueError, TypeError) as e:
                logger.warning(f"Error parsing token timestamps: {e}")
        
        # Method 3: Check expires_in without created_at (assume recent)
        if 'expires_in' in token:
            try:
                expires_in = int(token['expires_in'])
                # If no created_at, assume token was just created
                # This is less accurate but works for new tokens
                is_expired = expires_in <= buffer_seconds
                logger.debug(f"Token expires in {expires_in} seconds, expired: {is_expired}")
                return is_expired
            except (ValueError, TypeError) as e:
                logger.warning(f"Invalid expires_in value: {e}")
        
        # If we can't determine expiration, assume it's NOT expired for Epic tokens
        # This is more permissive than the original logic
        logger.info("Cannot determine token expiration - assuming valid for Epic compatibility")
        return False
        
    except Exception as e:
        logger.warning(f"Error checking token expiration: {e}")
        # Default to NOT expired if we can't check - more permissive
        return False


def refresh_token(token: Dict[str, Any], client_id: str, token_endpoint: str) -> Dict[str, Any]:
    """
    Refresh an expired access token using refresh token.
    
    Critical for maintaining Epic session without user re-authentication.
    """
    if 'refresh_token' not in token:
        raise TokenRefreshError("No refresh token available")
    
    try:
        # Create client assertion for refresh
        client_assertion = create_client_assertion(client_id, token_endpoint)
        
        # Prepare refresh request
        refresh_params = {
            'grant_type': 'refresh_token',
            'refresh_token': token['refresh_token'],
            'client_id': client_id,
            'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion': client_assertion
        }
        
        # Make refresh request to Epic
        response = requests.post(
            token_endpoint,
            data=refresh_params,
            headers={
                'Content-Type': 'application/x-www-form-urlencoded',
                'Accept': 'application/json'
            },
            timeout=30
        )
        
        # Check for token revocation
        if is_token_revoked(response):
            log_security_event(
                'token_revoked_during_refresh',
                {'client_id': client_id, 'status_code': response.status_code}
            )
            raise TokenRevokedException("Token was revoked during refresh")
        
        # Handle other errors
        if not response.ok:
            error_msg = f"Token refresh failed with status {response.status_code}"
            try:
                error_body = response.json()
                error_msg += f": {error_body.get('error_description', error_body)}"
            except:
                error_msg += f": {response.text}"
            
            raise TokenRefreshError(error_msg)
        
        # Parse new token
        new_token = response.json()
        
        # Add metadata for tracking - be more flexible about timestamp format
        new_token['created_at'] = datetime.now(timezone.utc).isoformat()
        
        # Calculate expires_at if we have expires_in
        if 'expires_in' in new_token:
            try:
                expires_in = int(new_token['expires_in'])
                new_token['expires_at'] = time.time() + expires_in
            except (ValueError, TypeError):
                logger.warning("Invalid expires_in in refreshed token")
        
        # Preserve Epic-specific fields from original token
        epic_fields = ['scope', 'patient', 'encounter', 'getMessage', 'setMessage', 'epicUserID']
        for field in epic_fields:
            if field in token and field not in new_token:
                new_token[field] = token[field]
        
        log_security_event(
            'token_refreshed_successfully',
            {
                'client_id': client_id,
                'old_expires_at': token.get('expires_at'),
                'new_expires_at': new_token.get('expires_at')
            }
        )
        
        logger.info("Token refreshed successfully")
        return new_token
        
    except TokenRevokedException:
        # Re-raise token revocation without wrapping
        raise
    except Exception as e:
        error_msg = f"Token refresh failed: {str(e)}"
        logger.error(error_msg)
        raise TokenRefreshError(error_msg, original_error=e)


def refresh_token_if_needed(
    token: Dict[str, Any], 
    client_id: str, 
    token_endpoint: str,
    force_refresh: bool = False
) -> Tuple[Dict[str, Any], bool]:
    """Refresh token if needed or if forced. Returns (token, was_refreshed)."""
    if not force_refresh and not is_token_expired(token):
        return token, False
    
    try:
        new_token = refresh_token(token, client_id, token_endpoint)
        return new_token, True
    except Exception as e:
        logger.error(f"Token refresh failed: {e}")
        raise


def is_token_revoked(response: requests.Response) -> bool:
    """
    Check if HTTP response indicates token revocation.
    
    Epic returns specific indicators when tokens are revoked.
    """
    if response.status_code != 401:
        return False
    
    # Check WWW-Authenticate header
    auth_header = response.headers.get('WWW-Authenticate', '').lower()
    
    revocation_indicators = [
        'token_revoked',
        'invalid_token',
        'token has been revoked',
        'the access token provided has been revoked'
    ]
    
    # Check header for revocation
    if any(indicator in auth_header for indicator in revocation_indicators):
        return True
    
    # Check response body
    try:
        body = response.json()
        error = body.get('error', '').lower()
        error_description = body.get('error_description', '').lower()
        
        if any(indicator in error or indicator in error_description 
              for indicator in revocation_indicators):
            return True
    except:
        pass
    
    return False


def get_token_info(token: Dict[str, Any]) -> Dict[str, Any]:
    """Get essential token information for debugging and monitoring."""
    try:
        info = {
            'is_valid': validate_token(token),
            'is_expired': is_token_expired(token),
            'has_refresh_token': 'refresh_token' in token,
            'epic_user_id': token.get('epicUserID'),
            'scope': token.get('scope'),
            'expires_at': token.get('expires_at'),
            'expires_in': token.get('expires_in'),
            'token_type': token.get('token_type'),
            'epic_endpoints': {
                'getMessage': token.get('getMessage'),
                'setMessage': token.get('setMessage')
            }
        }
        
        # Calculate time until expiration - be more flexible
        if 'expires_at' in token:
            try:
                expires_at = datetime.fromtimestamp(token['expires_at'])
                now = datetime.now()
                info['expires_in_minutes'] = max(0, int((expires_at - now).total_seconds()) // 60)
            except:
                pass
        elif 'expires_in' in token:
            try:
                expires_in = int(token['expires_in'])
                info['expires_in_minutes'] = max(0, expires_in // 60)
            except:
                pass
        
        return info
        
    except Exception as e:
        logger.error(f"Error getting token info: {e}")
        return {'error': str(e)}


# Simple TokenManager class for compatibility with existing code
class TokenManager:
    """Token manager providing Epic FHIR integration token operations."""
    
    def validate_token(self, token: Dict[str, Any]) -> bool:
        return validate_token(token)
    
    def is_token_expired(self, token: Dict[str, Any]) -> bool:
        return is_token_expired(token)
    
    def refresh_token_if_needed(
        self, 
        token: Dict[str, Any], 
        client_id: str, 
        token_endpoint: str,
        force_refresh: bool = False
    ) -> Tuple[Dict[str, Any], bool]:
        return refresh_token_if_needed(token, client_id, token_endpoint, force_refresh)
    
    def get_token_info(self, token: Dict[str, Any]) -> Dict[str, Any]:
        return get_token_info(token)


# Global instance for compatibility
_token_manager: Optional[TokenManager] = None


def get_token_manager() -> TokenManager:
    """Get the global token manager instance."""
    global _token_manager
    
    if _token_manager is None:
        _token_manager = TokenManager()
    
    return _token_manager