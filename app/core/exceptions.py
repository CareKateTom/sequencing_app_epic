"""
Custom exception classes for Epic FHIR Integration application.

This module provides a hierarchy of custom exceptions that improve error handling,
debugging, and user experience throughout the application.
"""

from typing import Optional, Dict, Any
import requests


class EpicFHIRError(Exception):
    """
    Base exception class for all Epic FHIR Integration errors.
    
    Provides common functionality for error logging, context preservation,
    and standardized error responses.
    """
    
    def __init__(
        self, 
        message: str, 
        error_code: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
        original_error: Optional[Exception] = None
    ):
        """
        Initialize base exception.
        
        Args:
            message: Human-readable error message
            error_code: Optional error code for programmatic handling
            context: Additional context information
            original_error: Original exception that caused this error
        """
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.context = context or {}
        self.original_error = original_error
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary for JSON serialization."""
        return {
            'error': self.__class__.__name__,
            'message': self.message,
            'error_code': self.error_code,
            'context': self.context
        }
    
    def __str__(self) -> str:
        """String representation including error code if available."""
        if self.error_code:
            return f"[{self.error_code}] {self.message}"
        return self.message


# Configuration and Setup Errors
class ConfigurationError(EpicFHIRError):
    """Raised when application configuration is invalid or missing."""
    pass


class SecretManagerError(EpicFHIRError):
    """Raised when secret retrieval from GCP Secret Manager fails."""
    pass


# Authentication and Authorization Errors
class AuthenticationError(EpicFHIRError):
    """Base class for authentication-related errors."""
    pass


class TokenError(AuthenticationError):
    """Base class for OAuth token-related errors."""
    pass


class TokenExpiredError(TokenError):
    """Raised when an OAuth token has expired."""
    
    def __init__(self, message: str = "Access token has expired", **kwargs):
        super().__init__(message, error_code="TOKEN_EXPIRED", **kwargs)


class TokenRevokedException(TokenError):
    """Raised when an OAuth token has been revoked."""
    
    def __init__(
        self, 
        message: str = "Token has been revoked", 
        original_error: Optional[Exception] = None,
        **kwargs
    ):
        super().__init__(
            message, 
            error_code="TOKEN_REVOKED", 
            original_error=original_error,
            **kwargs
        )


class TokenRefreshError(TokenError):
    """Raised when token refresh fails."""
    
    def __init__(self, message: str = "Failed to refresh access token", **kwargs):
        super().__init__(message, error_code="TOKEN_REFRESH_FAILED", **kwargs)


class InvalidTokenError(TokenError):
    """Raised when a token is malformed or invalid."""
    
    def __init__(self, message: str = "Invalid token format", **kwargs):
        super().__init__(message, error_code="INVALID_TOKEN", **kwargs)


class AuthorizationError(AuthenticationError):
    """Raised when authorization fails (e.g., insufficient permissions)."""
    
    def __init__(self, message: str = "Authorization failed", **kwargs):
        super().__init__(message, error_code="AUTHORIZATION_FAILED", **kwargs)


# FHIR API Errors
class FHIRError(EpicFHIRError):
    """Base class for FHIR API-related errors."""
    pass


class FHIRClientError(FHIRError):
    """Raised for FHIR client errors (4xx status codes)."""
    
    def __init__(
        self, 
        message: str, 
        status_code: Optional[int] = None,
        response_body: Optional[str] = None,
        **kwargs
    ):
        super().__init__(message, **kwargs)
        self.status_code = status_code
        self.response_body = response_body
        
        if status_code:
            self.context['status_code'] = status_code
        if response_body:
            self.context['response_body'] = response_body


class FHIRServerError(FHIRError):
    """Raised for FHIR server errors (5xx status codes)."""
    
    def __init__(
        self, 
        message: str, 
        status_code: Optional[int] = None,
        response_body: Optional[str] = None,
        **kwargs
    ):
        super().__init__(message, **kwargs)
        self.status_code = status_code
        self.response_body = response_body
        
        if status_code:
            self.context['status_code'] = status_code
        if response_body:
            self.context['response_body'] = response_body


class ResourceNotFoundError(FHIRClientError):
    """Raised when a FHIR resource is not found."""
    
    def __init__(self, resource_type: str, resource_id: str, **kwargs):
        message = f"{resource_type} with ID '{resource_id}' not found"
        super().__init__(
            message, 
            status_code=404, 
            error_code="RESOURCE_NOT_FOUND",
            context={'resource_type': resource_type, 'resource_id': resource_id},
            **kwargs
        )


class InvalidSearchParametersError(FHIRClientError):
    """Raised when FHIR search parameters are invalid."""
    
    def __init__(self, search_params: Dict[str, Any], **kwargs):
        message = f"Invalid search parameters: {search_params}"
        super().__init__(
            message,
            status_code=400,
            error_code="INVALID_SEARCH_PARAMS",
            context={'search_params': search_params},
            **kwargs
        )


# HL7 Processing Errors
class HL7Error(EpicFHIRError):
    """Base class for HL7 message processing errors."""
    pass


class HL7ParseError(HL7Error):
    """Raised when HL7 message parsing fails."""
    
    def __init__(
        self, 
        message: str, 
        segment: Optional[str] = None,
        field_position: Optional[int] = None,
        **kwargs
    ):
        super().__init__(message, error_code="HL7_PARSE_ERROR", **kwargs)
        
        if segment:
            self.context['segment'] = segment
        if field_position:
            self.context['field_position'] = field_position


class HL7ValidationError(HL7Error):
    """Raised when HL7 message validation fails."""
    
    def __init__(self, message: str, validation_errors: Optional[list] = None, **kwargs):
        super().__init__(message, error_code="HL7_VALIDATION_ERROR", **kwargs)
        
        if validation_errors:
            self.context['validation_errors'] = validation_errors


class HL7MessageError(HL7Error):
    """Raised when sending/receiving HL7 messages fails."""
    
    def __init__(
        self, 
        message: str, 
        operation: str,  # 'send' or 'receive'
        endpoint: Optional[str] = None,
        **kwargs
    ):
        super().__init__(message, error_code="HL7_MESSAGE_ERROR", **kwargs)
        self.context['operation'] = operation
        
        if endpoint:
            self.context['endpoint'] = endpoint


# Network and API Errors
class NetworkError(EpicFHIRError):
    """Base class for network-related errors."""
    pass


class APITimeoutError(NetworkError):
    """Raised when API requests timeout."""
    
    def __init__(self, timeout_seconds: Optional[float] = None, **kwargs):
        message = f"API request timed out after {timeout_seconds} seconds" if timeout_seconds else "API request timed out"
        super().__init__(message, error_code="API_TIMEOUT", **kwargs)
        
        if timeout_seconds:
            self.context['timeout_seconds'] = timeout_seconds


class APIConnectionError(NetworkError):
    """Raised when API connection fails."""
    
    def __init__(self, endpoint: Optional[str] = None, **kwargs):
        message = f"Failed to connect to API endpoint: {endpoint}" if endpoint else "Failed to connect to API"
        super().__init__(message, error_code="API_CONNECTION_ERROR", **kwargs)
        
        if endpoint:
            self.context['endpoint'] = endpoint


# Validation Errors
class ValidationError(EpicFHIRError):
    """Base class for data validation errors."""
    pass


class PatientDataValidationError(ValidationError):
    """Raised when patient data validation fails."""
    
    def __init__(self, patient_id: str, validation_errors: list, **kwargs):
        message = f"Patient data validation failed for ID '{patient_id}'"
        super().__init__(
            message,
            error_code="PATIENT_DATA_VALIDATION_ERROR",
            context={
                'patient_id': patient_id,
                'validation_errors': validation_errors
            },
            **kwargs
        )


# Utility Functions for Exception Handling
def handle_requests_error(response: requests.Response, context: Optional[Dict[str, Any]] = None) -> EpicFHIRError:
    """
    Convert requests.Response error to appropriate custom exception.
    
    Args:
        response: The failed HTTP response
        context: Additional context information
        
    Returns:
        Appropriate custom exception based on response status
    """
    status_code = response.status_code
    
    try:
        response_body = response.text
    except:
        response_body = None
    
    # Determine error type based on status code
    if status_code == 401:
        # Check if it's a token revocation
        if _is_token_revoked(response):
            return TokenRevokedException(
                "Token has been revoked",
                context=context
            )
        else:
            return AuthenticationError(
                f"Authentication failed: {response.reason}",
                context=context
            )
    
    elif status_code == 403:
        return AuthorizationError(
            f"Access forbidden: {response.reason}",
            context=context
        )
    
    elif status_code == 404:
        return FHIRClientError(
            f"Resource not found: {response.reason}",
            status_code=status_code,
            response_body=response_body,
            context=context
        )
    
    elif 400 <= status_code < 500:
        return FHIRClientError(
            f"Client error: {response.reason}",
            status_code=status_code,
            response_body=response_body,
            context=context
        )
    
    elif 500 <= status_code < 600:
        return FHIRServerError(
            f"Server error: {response.reason}",
            status_code=status_code,
            response_body=response_body,
            context=context
        )
    
    else:
        return NetworkError(
            f"Unexpected HTTP status: {status_code} {response.reason}",
            context=context
        )


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
        'token has been revoked',
        'the access token provided has been revoked'
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


def create_error_response(exception: EpicFHIRError, include_traceback: bool = False) -> Dict[str, Any]:
    """
    Create a standardized error response dictionary.
    
    Args:
        exception: The exception to convert
        include_traceback: Whether to include traceback information
        
    Returns:
        Dictionary suitable for JSON response
    """
    response = exception.to_dict()
    
    if include_traceback and exception.original_error:
        import traceback
        response['traceback'] = traceback.format_exception(
            type(exception.original_error),
            exception.original_error,
            exception.original_error.__traceback__
        )
    
    return response