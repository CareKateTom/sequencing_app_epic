"""
Exception classes for Epic FHIR Integration application.

Healthcare-focused exception handling prioritizing security and compliance.
Follows principle: "Secure and compliant, not enterprise-ready" 

Maximum 4 exception types as per design principles.
"""

from typing import Optional, Dict, Any
import requests

from app.core.logging import get_logger, log_security_event

logger = get_logger(__name__)


class EpicFHIRError(Exception):
    """
    Base exception class for all Epic FHIR Integration errors.
    
    Provides security logging and context preservation for healthcare compliance.
    """
    
    def __init__(
        self, 
        message: str, 
        context: Optional[Dict[str, Any]] = None,
        log_security: bool = True
    ):
        """
        Initialize base exception.
        
        Args:
            message: Human-readable error message
            context: Additional context information for logging
            log_security: Whether to log this as a security event
        """
        super().__init__(message)
        self.message = message
        self.context = context or {}
        
        # Log as security event for healthcare compliance monitoring
        if log_security:
            log_security_event(
                'application_error',
                {
                    'error_type': self.__class__.__name__,
                    'error_message': message,
                    'context': self.context
                },
                level='ERROR'
            )
    
    def __str__(self) -> str:
        """String representation of the error."""
        return self.message


class AuthenticationError(EpicFHIRError):
    """
    Authentication and authorization errors.
    
    Covers OAuth token issues, Epic authentication failures, and access control.
    """
    
    def __init__(self, message: str = "Authentication failed", **kwargs):
        super().__init__(message, **kwargs)


class FHIRError(EpicFHIRError):
    """
    FHIR API interaction errors.
    
    Covers Epic FHIR server errors, client errors, and resource access issues.
    """
    
    def __init__(
        self, 
        message: str, 
        status_code: Optional[int] = None,
        **kwargs
    ):
        super().__init__(message, **kwargs)
        self.status_code = status_code
        if status_code:
            self.context['status_code'] = status_code


class HL7Error(EpicFHIRError):
    """
    HL7 message processing errors.
    
    Covers HL7 parsing, validation, and bidirectional messaging issues.
    """
    
    def __init__(
        self, 
        message: str, 
        segment: Optional[str] = None,
        **kwargs
    ):
        super().__init__(message, **kwargs)
        if segment:
            self.context['segment'] = segment


# Utility Functions for Error Handling

def handle_requests_error(response: requests.Response) -> EpicFHIRError:
    """
    Convert requests.Response error to appropriate exception.
    
    Args:
        response: The failed HTTP response
        
    Returns:
        Appropriate exception based on response status
    """
    status_code = response.status_code
    
    try:
        response_body = response.text
    except:
        response_body = None
    
    context = {
        'status_code': status_code,
        'response_body': response_body[:200] if response_body else None  # Limit for security
    }
    
    # Determine error type based on status code
    if status_code == 401:
        # Check if it's a token revocation
        if _is_token_revoked(response):
            return AuthenticationError("Token has been revoked", context=context)
        else:
            return AuthenticationError(f"Authentication failed: {response.reason}", context=context)
    
    elif status_code == 403:
        return AuthenticationError(f"Access forbidden: {response.reason}", context=context)
    
    elif 400 <= status_code < 500:
        return FHIRError(f"Client error: {response.reason}", status_code=status_code, context=context)
    
    elif 500 <= status_code < 600:
        return FHIRError(f"Server error: {response.reason}", status_code=status_code, context=context)
    
    else:
        return EpicFHIRError(f"Unexpected HTTP status: {status_code} {response.reason}", context=context)


def _is_token_revoked(response: requests.Response) -> bool:
    """
    Check if a 401 response indicates token revocation.
    
    Args:
        response: The HTTP response to check
        
    Returns:
        True if the response indicates token revocation
    """
    if response.status_code != 401:
        return False
    
    # Check WWW-Authenticate header
    auth_header = response.headers.get('WWW-Authenticate', '').lower()
    
    # Common revocation indicators
    revocation_indicators = [
        'token_revoked',
        'invalid_token',
        'token has been revoked'
    ]
    
    # Check header for revocation indicators
    if any(indicator in auth_header for indicator in revocation_indicators):
        return True
    
    # Check response body if JSON
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


# Legacy Exception Aliases for Backward Compatibility
# These map to our simplified 4-exception structure

TokenRevokedException = AuthenticationError
TokenExpiredError = AuthenticationError
TokenRefreshError = AuthenticationError
TokenError = AuthenticationError
InvalidTokenError = AuthenticationError
AuthorizationError = AuthenticationError

FHIRClientError = FHIRError
FHIRServerError = FHIRError
ResourceNotFoundError = FHIRError
InvalidSearchParametersError = FHIRError
NetworkError = FHIRError
APITimeoutError = FHIRError
APIConnectionError = FHIRError

HL7ParseError = HL7Error
HL7ValidationError = HL7Error
HL7MessageError = HL7Error

ConfigurationError = EpicFHIRError
SecretManagerError = EpicFHIRError
ValidationError = EpicFHIRError
PatientDataValidationError = EpicFHIRError