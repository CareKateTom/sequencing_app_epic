"""
OAuth2 token management for Epic FHIR Integration.

This module provides comprehensive token management including:
- JWT creation and validation for client assertions
- Token refresh with automatic retry logic
- Token validation and expiration checking
- JWKS endpoint for public key distribution
- Token revocation detection and handling
- Secure token storage and caching
"""

import os
import time
import secrets
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, Tuple
from pathlib import Path
import base64
import jwt
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import requests

from app.core.exceptions import (
    TokenError, TokenExpiredError, TokenRevokedException, 
    TokenRefreshError, InvalidTokenError
)
from app.core.logging import get_logger, log_performance, log_security_event
from app.core.secrets import get_secret_manager

logger = get_logger(__name__)


class JWKSManager:
    """
    Manages JWKS (JSON Web Key Set) for OAuth2 client authentication.
    
    Handles loading, caching, and serving of public keys for JWT verification.
    """
    
    def __init__(self, private_key_path: str = 'keys/private.pem'):
        """
        Initialize JWKS manager.
        
        Args:
            private_key_path: Path to private key file
        """
        self.private_key_path = private_key_path
        self._jwks_cache: Optional[Dict[str, Any]] = None
        self._cache_timestamp: Optional[float] = None
        self._cache_ttl = 3600  # 1 hour cache TTL
    
    def load_private_key(self) -> Any:
        """
        Load private key from file.
        
        Returns:
            Cryptography private key object
            
        Raises:
            TokenError: If private key cannot be loaded
        """
        try:
            key_path = Path(self.private_key_path)
            
            if not key_path.exists():
                raise TokenError(f"Private key file not found: {key_path}")
            
            with open(key_path, 'rb') as f:
                private_key = serialization.load_pem_private_key(
                    f.read(), 
                    password=None
                )
            
            logger.debug(f"Successfully loaded private key from {key_path}")
            return private_key
            
        except Exception as e:
            error_msg = f"Failed to load private key: {str(e)}"
            logger.error(error_msg)
            raise TokenError(error_msg, original_error=e)
    
    def load_jwks(self, force_refresh: bool = False) -> Dict[str, Any]:
        """
        Load or generate JWKS from private key.
        
        Args:
            force_refresh: Force regeneration of JWKS
            
        Returns:
            JWKS dictionary
        """
        # Check cache first
        if (not force_refresh and 
            self._jwks_cache and 
            self._cache_timestamp and 
            time.time() - self._cache_timestamp < self._cache_ttl):
            return self._jwks_cache
        
        try:
            with log_performance("jwks_generation", logger):
                private_key = self.load_private_key()
                
                # Get public key from private key
                public_key = private_key.public_key()
                public_numbers = public_key.public_numbers()
                
                # Convert to JWK format
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
                
                # Cache the result
                self._jwks_cache = jwks
                self._cache_timestamp = time.time()
                
                logger.info("JWKS generated successfully")
                return jwks
                
        except Exception as e:
            error_msg = f"Failed to generate JWKS: {str(e)}"
            logger.error(error_msg)
            raise TokenError(error_msg, original_error=e)
    
    def create_client_assertion(
        self, 
        client_id: str, 
        token_endpoint: str, 
        expiration_minutes: int = 5
    ) -> str:
        """
        Create JWT client assertion for OAuth2 authentication.
        
        Args:
            client_id: OAuth2 client ID
            token_endpoint: Token endpoint URL
            expiration_minutes: JWT expiration time in minutes
            
        Returns:
            Signed JWT assertion string
        """
        try:
            with log_performance("client_assertion_creation", logger):
                private_key = self.load_private_key()
                
                now = datetime.now(timezone.utc)
                
                claims = {
                    'iss': client_id,
                    'sub': client_id,
                    'aud': token_endpoint,
                    'jti': secrets.token_hex(16),
                    'exp': now + timedelta(minutes=expiration_minutes),
                    'iat': now,
                    'nbf': now
                }
                
                # Load private key as bytes for PyJWT
                with open(self.private_key_path, 'rb') as f:
                    private_key_bytes = f.read()
                
                assertion = jwt.encode(
                    claims,
                    private_key_bytes,
                    algorithm='RS384',
                    headers={'kid': 'epic-fhir-integration-key'}
                )
                
                logger.debug("Client assertion created successfully")
                return assertion
                
        except Exception as e:
            error_msg = f"Failed to create client assertion: {str(e)}"
            logger.error(error_msg)
            raise TokenError(error_msg, original_error=e)


class TokenValidator:
    """
    Validates OAuth2 tokens and checks expiration status.
    """
    
    @staticmethod
    def validate_token_structure(token: Dict[str, Any]) -> None:
        """
        Validate basic token structure.
        
        Args:
            token: Token dictionary to validate
            
        Raises:
            InvalidTokenError: If token structure is invalid
        """
        required_fields = ['access_token', 'token_type']
        
        for field in required_fields:
            if field not in token:
                raise InvalidTokenError(f"Token missing required field: {field}")
        
        if not token['access_token']:
            raise InvalidTokenError("Access token is empty")
        
        if token.get('token_type', '').lower() != 'bearer':
            logger.warning(f"Unexpected token type: {token.get('token_type')}")
    
    @staticmethod
    def is_token_expired(token: Dict[str, Any], buffer_seconds: int = 300) -> bool:
        """
        Check if token is expired or will expire soon.
        
        Args:
            token: Token dictionary
            buffer_seconds: Buffer time before actual expiration
            
        Returns:
            True if token is expired or will expire within buffer time
        """
        try:
            # Check expires_at timestamp (preferred)
            if 'expires_at' in token:
                expires_at = datetime.fromtimestamp(token['expires_at'])
                return datetime.now() + timedelta(seconds=buffer_seconds) >= expires_at
            
            # Fallback to expires_in + created_at
            if 'expires_in' in token and 'created_at' in token:
                created_at_str = token['created_at']
                if isinstance(created_at_str, str):
                    created_at = datetime.fromisoformat(created_at_str.replace('Z', '+00:00'))
                else:
                    created_at = created_at_str
                
                expires_at = created_at + timedelta(seconds=token['expires_in'])
                return datetime.now(timezone.utc) + timedelta(seconds=buffer_seconds) >= expires_at
            
            # If we can't determine expiration, assume expired
            logger.warning("Cannot determine token expiration, assuming expired")
            return True
            
        except Exception as e:
            logger.warning(f"Error checking token expiration: {e}")
            return True
    
    @staticmethod
    def validate_token(token: Dict[str, Any]) -> None:
        """
        Comprehensive token validation.
        
        Args:
            token: Token dictionary to validate
            
        Raises:
            InvalidTokenError: If token is invalid
            TokenExpiredError: If token is expired
        """
        TokenValidator.validate_token_structure(token)
        
        if TokenValidator.is_token_expired(token):
            raise TokenExpiredError("Access token has expired")
        
        logger.debug("Token validation passed")


class TokenRefreshManager:
    """
    Manages OAuth2 token refresh operations with retry logic and error handling.
    """
    
    def __init__(self, jwks_manager: JWKSManager):
        """
        Initialize token refresh manager.
        
        Args:
            jwks_manager: JWKS manager for client assertion creation
        """
        self.jwks_manager = jwks_manager
        self.max_retries = 3
        self.retry_delay = 1.0  # Base delay between retries
    
    def refresh_token(
        self, 
        token: Dict[str, Any], 
        client_id: str, 
        token_endpoint: str
    ) -> Dict[str, Any]:
        """
        Refresh an expired access token.
        
        Args:
            token: Current token dictionary
            client_id: OAuth2 client ID
            token_endpoint: Token endpoint URL
            
        Returns:
            New token dictionary
            
        Raises:
            TokenRefreshError: If refresh fails
            TokenRevokedException: If token is revoked
        """
        if 'refresh_token' not in token:
            raise TokenRefreshError("No refresh token available")
        
        for attempt in range(self.max_retries):
            try:
                with log_performance(f"token_refresh_attempt_{attempt + 1}", logger):
                    return self._attempt_token_refresh(token, client_id, token_endpoint)
                    
            except TokenRevokedException:
                # Don't retry revoked tokens
                raise
                
            except Exception as e:
                logger.warning(
                    f"Token refresh attempt {attempt + 1} failed: {e}",
                    extra={'attempt': attempt + 1, 'max_retries': self.max_retries}
                )
                
                if attempt == self.max_retries - 1:
                    # Last attempt failed
                    raise TokenRefreshError(f"Token refresh failed after {self.max_retries} attempts: {e}")
                
                # Wait before retry with exponential backoff
                time.sleep(self.retry_delay * (2 ** attempt))
        
        raise TokenRefreshError("Token refresh failed: max retries exceeded")
    
    def _attempt_token_refresh(
        self, 
        token: Dict[str, Any], 
        client_id: str, 
        token_endpoint: str
    ) -> Dict[str, Any]:
        """
        Single attempt to refresh token.
        
        Args:
            token: Current token dictionary
            client_id: OAuth2 client ID
            token_endpoint: Token endpoint URL
            
        Returns:
            New token dictionary
        """
        # Create client assertion
        client_assertion = self.jwks_manager.create_client_assertion(
            client_id, 
            token_endpoint
        )
        
        # Prepare refresh request
        refresh_params = {
            'grant_type': 'refresh_token',
            'refresh_token': token['refresh_token'],
            'client_id': client_id,
            'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion': client_assertion
        }
        
        # Make refresh request
        response = requests.post(
            token_endpoint,
            data=refresh_params,
            headers={
                'Content-Type': 'application/x-www-form-urlencoded',
                'Accept': 'application/json'
            },
            timeout=30
        )
        
        # Check for revocation
        if self._is_token_revoked(response):
            log_security_event(
                'token_revoked',
                {'client_id': client_id, 'status_code': response.status_code}
            )
            raise TokenRevokedException("Token has been revoked during refresh")
        
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
        
        # Add metadata
        new_token['created_at'] = datetime.now(timezone.utc).isoformat()
        new_token['expires_at'] = time.time() + new_token.get('expires_in', 3600)
        
        # Preserve original token fields if not in new token
        for key in ['scope', 'patient', 'encounter', 'getMessage', 'setMessage']:
            if key in token and key not in new_token:
                new_token[key] = token[key]
        
        logger.info("Token refreshed successfully")
        return new_token
    
    def _is_token_revoked(self, response: requests.Response) -> bool:
        """
        Check if response indicates token revocation.
        
        Args:
            response: HTTP response to check
            
        Returns:
            True if token appears to be revoked
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
        
        # Check header for revocation indicators
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


class TokenManager:
    """
    Comprehensive token management system for Epic FHIR Integration.
    
    Provides high-level interface for all token operations including:
    - Token validation and refresh
    - Client assertion creation
    - JWKS management
    - Token caching and storage
    """
    
    def __init__(self, private_key_path: str = 'keys/private.pem'):
        """
        Initialize token manager.
        
        Args:
            private_key_path: Path to private key file
        """
        self.jwks_manager = JWKSManager(private_key_path)
        self.refresh_manager = TokenRefreshManager(self.jwks_manager)
        self.validator = TokenValidator()
        
        # Cache for active tokens (in production, consider Redis)
        self._token_cache: Dict[str, Dict[str, Any]] = {}
    
    def get_jwks(self) -> Dict[str, Any]:
        """
        Get JWKS for public key distribution.
        
        Returns:
            JWKS dictionary
        """
        return self.jwks_manager.load_jwks()
    
    def create_client_assertion(self, client_id: str, token_endpoint: str) -> str:
        """
        Create client assertion for OAuth2 authentication.
        
        Args:
            client_id: OAuth2 client ID
            token_endpoint: Token endpoint URL
            
        Returns:
            Signed JWT assertion
        """
        return self.jwks_manager.create_client_assertion(client_id, token_endpoint)
    
    def validate_token(self, token: Dict[str, Any]) -> bool:
        """
        Validate token structure and expiration.
        
        Args:
            token: Token dictionary to validate
            
        Returns:
            True if token is valid
        """
        try:
            self.validator.validate_token(token)
            return True
        except (InvalidTokenError, TokenExpiredError):
            return False
    
    def is_token_expired(self, token: Dict[str, Any], buffer_seconds: int = 300) -> bool:
        """
        Check if token needs refresh.
        
        Args:
            token: Token dictionary
            buffer_seconds: Buffer time before expiration
            
        Returns:
            True if token needs refresh
        """
        return self.validator.is_token_expired(token, buffer_seconds)
    
    def refresh_token_if_needed(
        self, 
        token: Dict[str, Any], 
        client_id: str, 
        token_endpoint: str,
        force_refresh: bool = False
    ) -> Tuple[Dict[str, Any], bool]:
        """
        Refresh token if needed or if forced.
        
        Args:
            token: Current token dictionary
            client_id: OAuth2 client ID
            token_endpoint: Token endpoint URL
            force_refresh: Force refresh even if not expired
            
        Returns:
            Tuple of (token, was_refreshed)
        """
        if not force_refresh and not self.is_token_expired(token):
            return token, False
        
        try:
            new_token = self.refresh_manager.refresh_token(
                token, 
                client_id, 
                token_endpoint
            )
            
            log_security_event(
                'token_refreshed',
                {
                    'client_id': client_id,
                    'forced': force_refresh,
                    'old_expires_at': token.get('expires_at'),
                    'new_expires_at': new_token.get('expires_at')
                }
            )
            
            return new_token, True
            
        except Exception as e:
            logger.error(f"Token refresh failed: {e}")
            raise
    
    def revoke_token(self, token: Dict[str, Any], revocation_endpoint: str) -> bool:
        """
        Revoke a token (if revocation endpoint is available).
        
        Args:
            token: Token to revoke
            revocation_endpoint: Token revocation endpoint
            
        Returns:
            True if revocation succeeded
        """
        try:
            response = requests.post(
                revocation_endpoint,
                data={
                    'token': token.get('refresh_token', token.get('access_token')),
                    'token_type_hint': 'refresh_token' if 'refresh_token' in token else 'access_token'
                },
                timeout=10
            )
            
            success = response.status_code in [200, 204]
            
            if success:
                log_security_event(
                    'token_revoked',
                    {'revocation_endpoint': revocation_endpoint, 'status_code': response.status_code}
                )
            else:
                logger.warning(f"Token revocation failed: {response.status_code}")
            
            return success
            
        except Exception as e:
            logger.error(f"Token revocation error: {e}")
            return False
    
    def get_token_info(self, token: Dict[str, Any]) -> Dict[str, Any]:
        """
        Get token information and metadata.
        
        Args:
            token: Token dictionary
            
        Returns:
            Token information dictionary
        """
        try:
            info = {
                'is_valid': self.validate_token(token),
                'is_expired': self.is_token_expired(token),
                'token_type': token.get('token_type'),
                'scope': token.get('scope'),
                'expires_at': token.get('expires_at'),
                'created_at': token.get('created_at'),
                'has_refresh_token': 'refresh_token' in token,
                'epic_endpoints': {
                    'getMessage': token.get('getMessage'),
                    'setMessage': token.get('setMessage')
                }
            }
            
            if 'expires_at' in token:
                try:
                    expires_at = datetime.fromtimestamp(token['expires_at'])
                    now = datetime.now()
                    info['expires_in_seconds'] = max(0, int((expires_at - now).total_seconds()))
                    info['expires_in_minutes'] = max(0, info['expires_in_seconds'] // 60)
                except:
                    pass
            
            return info
            
        except Exception as e:
            logger.error(f"Error getting token info: {e}")
            return {'error': str(e)}


# Global token manager instance
_token_manager: Optional[TokenManager] = None


def get_token_manager() -> TokenManager:
    """
    Get the global token manager instance.
    
    Returns:
        TokenManager instance
    """
    global _token_manager
    
    if _token_manager is None:
        _token_manager = TokenManager()
    
    return _token_manager


# Convenience functions for common operations
def create_client_assertion(client_id: str, token_endpoint: str) -> str:
    """
    Create client assertion using global token manager.
    
    Args:
        client_id: OAuth2 client ID
        token_endpoint: Token endpoint URL
        
    Returns:
        Signed JWT assertion
    """
    manager = get_token_manager()
    return manager.create_client_assertion(client_id, token_endpoint)


def load_jwks() -> Dict[str, Any]:
    """
    Load JWKS using global token manager.
    
    Returns:
        JWKS dictionary
    """
    manager = get_token_manager()
    return manager.get_jwks()


def validate_token(token: Dict[str, Any]) -> bool:
    """
    Validate token using global token manager.
    
    Args:
        token: Token dictionary
        
    Returns:
        True if valid
    """
    manager = get_token_manager()
    return manager.validate_token(token)


def refresh_token_if_needed(
    token: Dict[str, Any], 
    client_id: str, 
    token_endpoint: str
) -> Tuple[Dict[str, Any], bool]:
    """
    Refresh token if needed using global token manager.
    
    Args:
        token: Current token
        client_id: OAuth2 client ID
        token_endpoint: Token endpoint URL
        
    Returns:
        Tuple of (token, was_refreshed)
    """
    manager = get_token_manager()
    return manager.refresh_token_if_needed(token, client_id, token_endpoint)