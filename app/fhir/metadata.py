"""
Epic OAuth metadata retrieval for HL7 Integration.

Simplified to extract only OAuth2 endpoints needed for authentication.
Removed FHIR-specific capability checking and resource analysis.
"""

import requests
from typing import Dict, Any

from app.core.exceptions import NetworkError, EpicHL7Error
from app.core.logging import get_logger, log_security_event

logger = get_logger(__name__)


def get_epic_metadata(fhir_base_url: str, timeout: int = 30) -> Dict[str, Any]:
    """
    Fetch Epic metadata to extract OAuth2 endpoints.
    
    Simplified version that only retrieves what's needed for authentication.
    
    Args:
        fhir_base_url: Base URL of Epic FHIR server
        timeout: Request timeout in seconds
        
    Returns:
        Dictionary containing OAuth endpoints
        
    Raises:
        NetworkError: If metadata retrieval fails
    """
    try:
        metadata_url = f"{fhir_base_url.rstrip('/')}/metadata"
        
        logger.info(f"Fetching Epic metadata for OAuth endpoints from: {metadata_url}")
        
        # Make request with appropriate headers
        headers = {
            'Accept': 'application/json+fhir',
            'Content-Type': 'application/json',
            'User-Agent': 'Epic-HL7-Integration/2.0'
        }
        
        response = requests.get(
            metadata_url, 
            headers=headers, 
            timeout=timeout
        )
        response.raise_for_status()
        
        # Parse JSON response
        metadata_json = response.json()
        
        # Extract OAuth endpoints
        auth_endpoints = _extract_auth_endpoints(metadata_json)
        
        if not auth_endpoints.get('authorize') or not auth_endpoints.get('token'):
            raise EpicHL7Error("Epic metadata missing required OAuth endpoints")
        
        # Log successful retrieval
        log_security_event(
            'oauth_metadata_retrieved',
            {
                'fhir_server': fhir_base_url,
                'has_authorize': bool(auth_endpoints.get('authorize')),
                'has_token': bool(auth_endpoints.get('token')),
                'success': True
            }
        )
        
        logger.info("Successfully retrieved OAuth endpoints from Epic metadata")
        
        # Return simplified metadata focused on OAuth
        return {
            'auth_endpoints': auth_endpoints,
            'fhir_server': fhir_base_url
        }
        
    except requests.exceptions.Timeout:
        error_msg = f"Timeout retrieving Epic metadata from {fhir_base_url}"
        logger.error(error_msg)
        raise NetworkError(error_msg)
        
    except requests.exceptions.ConnectionError as e:
        error_msg = f"Connection error retrieving Epic metadata: {str(e)}"
        logger.error(error_msg)
        raise NetworkError(error_msg)
        
    except requests.exceptions.HTTPError as e:
        error_msg = f"HTTP error retrieving Epic metadata: {e.response.status_code}"
        logger.error(error_msg)
        
        # Log security event for HTTP errors
        log_security_event(
            'oauth_metadata_http_error',
            {
                'fhir_server': fhir_base_url,
                'status_code': e.response.status_code,
                'error': str(e)
            },
            level='ERROR'
        )
        
        raise NetworkError(error_msg, status_code=e.response.status_code)
        
    except Exception as e:
        error_msg = f"Unexpected error retrieving Epic metadata: {str(e)}"
        logger.error(error_msg)
        raise EpicHL7Error(error_msg)


def _extract_auth_endpoints(metadata: Dict[str, Any]) -> Dict[str, str]:
    """
    Extract OAuth2 authorization and token endpoints from capability statement.
    
    Handles both FHIR DSTU2 and R4 formats, but only extracts OAuth endpoints.
    Epic includes these in the security extension.
    
    Args:
        metadata: Raw metadata JSON from Epic
        
    Returns:
        Dictionary with OAuth endpoints
    """
    endpoints = {}
    
    try:
        # Navigate to REST security extension
        rest_resources = metadata.get('rest', [])
        if not rest_resources:
            logger.warning("No REST resources found in Epic metadata")
            return endpoints
        
        security = rest_resources[0].get('security', {})
        extensions = security.get('extension', [])
        
        # Find OAuth URI extension
        oauth_extension = None
        for ext in extensions:
            if ext.get('url') == 'http://fhir-registry.smarthealthit.org/StructureDefinition/oauth-uris':
                oauth_extension = ext.get('extension', [])
                break
        
        if oauth_extension:
            for endpoint_ext in oauth_extension:
                url_type = endpoint_ext.get('url')
                endpoint_url = endpoint_ext.get('valueUri')
                
                if url_type == 'authorize' and endpoint_url:
                    endpoints['authorize'] = endpoint_url
                elif url_type == 'token' and endpoint_url:
                    endpoints['token'] = endpoint_url
                elif url_type == 'revoke' and endpoint_url:
                    endpoints['revoke'] = endpoint_url
        
        if endpoints:
            logger.info(f"Found OAuth endpoints: {list(endpoints.keys())}")
        else:
            logger.warning("No OAuth endpoints found in Epic metadata")
            
    except (KeyError, TypeError, IndexError) as e:
        logger.warning(f"Failed to parse OAuth endpoints from metadata: {e}")
    
    return endpoints


# Legacy class for backward compatibility
class EpicFHIRMetadata:
    """
    Legacy compatibility wrapper for Epic metadata.
    
    Simplified to only provide OAuth endpoint access.
    """
    
    def __init__(self, metadata_dict: Dict[str, Any]):
        """Initialize with metadata dictionary."""
        self.auth_endpoints = metadata_dict.get('auth_endpoints', {})
        self.fhir_server = metadata_dict.get('fhir_server')
    
    def get_oauth_endpoints(self) -> Dict[str, str]:
        """Get OAuth2 endpoints for authentication."""
        return self.auth_endpoints.copy()
    
    def has_smart_capabilities(self) -> bool:
        """Check if server supports SMART on FHIR capabilities."""
        return bool(self.auth_endpoints.get('authorize') and self.auth_endpoints.get('token'))