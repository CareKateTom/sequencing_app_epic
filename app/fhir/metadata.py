"""
Epic FHIR metadata parsing and capability statement handling.

Updated to handle both FHIR DSTU2 and R4 versions.
Healthcare-focused metadata processing for Epic FHIR servers.
Follows principle: "Secure and compliant, not enterprise-ready"
"""

import requests
from typing import Dict, List, Optional, Any

from app.core.exceptions import FHIRError, NetworkError
from app.core.logging import get_logger, log_security_event

logger = get_logger(__name__)


class EpicFHIRMetadata:
    """
    Epic FHIR server metadata and capability statement parser.
    
    Supports both FHIR DSTU2 (Conformance) and R4 (CapabilityStatement) formats.
    Simple processing focused on OAuth2 endpoints and basic capabilities.
    """
    
    def __init__(self, metadata_json: Dict[str, Any]):
        """Initialize metadata parser with capability statement."""
        self.raw_metadata = metadata_json
        self.resource_type = metadata_json.get('resourceType')
        self.fhir_version = metadata_json.get('fhirVersion')
        self.software_version = self._extract_software_version(metadata_json)
        
        # Detect FHIR version from resource type
        self.is_dstu2 = self.resource_type == 'Conformance'
        self.is_r4 = self.resource_type == 'CapabilityStatement'
        
        # Extract OAuth2 endpoints for authentication
        self.auth_endpoints = self._extract_auth_endpoints(metadata_json)
        
        # Extract supported resources and operations
        self.rest_capabilities = self._extract_rest_capabilities(metadata_json)
        
        logger.info(f"Parsed Epic FHIR metadata (version: {self.fhir_version}, type: {self.resource_type})")
    
    def _extract_software_version(self, metadata: Dict[str, Any]) -> Optional[str]:
        """Extract Epic software version information."""
        software = metadata.get('software', {})
        return software.get('version')
    
    def _extract_auth_endpoints(self, metadata: Dict[str, Any]) -> Dict[str, str]:
        """
        Extract OAuth2 authorization and token endpoints from capability statement.
        
        Handles both FHIR DSTU2 and R4 formats.
        Epic includes these in the security extension.
        """
        endpoints = {}
        
        try:
            # Navigate to REST security extension
            rest_resources = metadata.get('rest', [])
            if not rest_resources:
                logger.warning("No REST resources found in FHIR metadata")
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
                logger.warning("No OAuth endpoints found in FHIR metadata")
                
        except (KeyError, TypeError, IndexError) as e:
            logger.warning(f"Failed to parse OAuth endpoints from metadata: {e}")
        
        return endpoints
    
    def _extract_rest_capabilities(self, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Extract REST capabilities for supported resources."""
        capabilities = {
            'resources': {},
            'interactions': [],
            'search_params': []
        }
        
        try:
            rest_resources = metadata.get('rest', [])
            if not rest_resources:
                return capabilities
            
            rest_config = rest_resources[0]
            
            # Extract system-level interactions
            system_interactions = rest_config.get('interaction', [])
            capabilities['interactions'] = [
                interaction.get('code') for interaction in system_interactions
            ]
            
            # Extract resource-specific capabilities
            resources = rest_config.get('resource', [])
            for resource in resources:
                resource_type = resource.get('type')
                if not resource_type:
                    continue
                
                capabilities['resources'][resource_type] = {
                    'interactions': [
                        interaction.get('code') 
                        for interaction in resource.get('interaction', [])
                    ],
                    'search_params': [
                        param.get('name') 
                        for param in resource.get('searchParam', [])
                    ],
                    'versioning': resource.get('versioning'),
                    'conditional_read': resource.get('conditionalRead'),
                    'conditional_create': resource.get('conditionalCreate'),
                    'conditional_update': resource.get('conditionalUpdate'),
                    'conditional_delete': resource.get('conditionalDelete')
                }
        
        except (KeyError, TypeError) as e:
            logger.warning(f"Failed to parse REST capabilities: {e}")
        
        return capabilities
    
    def get_oauth_endpoints(self) -> Dict[str, str]:
        """Get OAuth2 endpoints for authentication."""
        return self.auth_endpoints.copy()
    
    def supports_resource(self, resource_type: str) -> bool:
        """Check if server supports a specific FHIR resource type."""
        return resource_type in self.rest_capabilities.get('resources', {})
    
    def get_resource_interactions(self, resource_type: str) -> List[str]:
        """Get supported interactions for a resource type."""
        resource_config = self.rest_capabilities.get('resources', {}).get(resource_type, {})
        return resource_config.get('interactions', [])
    
    def get_search_parameters(self, resource_type: str) -> List[str]:
        """Get supported search parameters for a resource type."""
        resource_config = self.rest_capabilities.get('resources', {}).get(resource_type, {})
        return resource_config.get('search_params', [])
    
    def has_smart_capabilities(self) -> bool:
        """Check if server supports SMART on FHIR capabilities."""
        return bool(self.auth_endpoints.get('authorize') and self.auth_endpoints.get('token'))
    
    def get_capability_summary(self) -> Dict[str, Any]:
        """Get summary of server capabilities for debugging."""
        return {
            'fhir_version': self.fhir_version,
            'resource_type': self.resource_type,
            'is_dstu2': self.is_dstu2,
            'is_r4': self.is_r4,
            'software_version': self.software_version,
            'oauth_endpoints': list(self.auth_endpoints.keys()),
            'supported_resources': list(self.rest_capabilities.get('resources', {}).keys()),
            'system_interactions': self.rest_capabilities.get('interactions', []),
            'has_smart_support': self.has_smart_capabilities()
        }


def get_epic_metadata(fhir_base_url: str, timeout: int = 30) -> EpicFHIRMetadata:
    """
    Fetch and parse Epic FHIR metadata/capability statement.
    
    Supports both FHIR DSTU2 and R4 versions.
    
    Args:
        fhir_base_url: Base URL of Epic FHIR server
        timeout: Request timeout in seconds
        
    Returns:
        Parsed Epic FHIR metadata
        
    Raises:
        FHIRError: If metadata retrieval or parsing fails
    """
    try:
        metadata_url = f"{fhir_base_url.rstrip('/')}/metadata"
        
        logger.info(f"Fetching Epic FHIR metadata from: {metadata_url}")
        
        # Make request with appropriate headers
        headers = {
            'Accept': 'application/json+fhir',
            'Content-Type': 'application/json',
            'User-Agent': 'Epic-FHIR-Integration/1.0'
        }
        
        response = requests.get(
            metadata_url, 
            headers=headers, 
            timeout=timeout
        )
        response.raise_for_status()
        
        # Parse JSON response
        metadata_json = response.json()
        
        # Validate basic structure - handle both DSTU2 and R4
        resource_type = metadata_json.get('resourceType')
        
        if resource_type not in ['CapabilityStatement', 'Conformance']:
            raise FHIRError(f"Expected CapabilityStatement (R4) or Conformance (DSTU2), got {resource_type}")
        
        # Log successful retrieval with version detection
        fhir_version_detected = "DSTU2" if resource_type == 'Conformance' else "R4"
        
        log_security_event(
            'fhir_metadata_retrieved',
            {
                'fhir_server': fhir_base_url,
                'resource_type': resource_type,
                'fhir_version_detected': fhir_version_detected,
                'fhir_version': metadata_json.get('fhirVersion'),
                'software_name': metadata_json.get('software', {}).get('name'),
                'success': True
            }
        )
        
        # Parse metadata
        parsed_metadata = EpicFHIRMetadata(metadata_json)
        
        # Validate OAuth endpoints for Epic integration
        if not parsed_metadata.has_smart_capabilities():
            logger.warning("Epic FHIR server does not appear to support SMART on FHIR")
        
        # Log FHIR version compatibility info
        if parsed_metadata.is_dstu2:
            logger.info("Epic server using FHIR DSTU2 - compatibility mode enabled")
        elif parsed_metadata.is_r4:
            logger.info("Epic server using FHIR R4 - native mode")
        
        return parsed_metadata
        
    except requests.exceptions.Timeout:
        error_msg = f"Timeout retrieving Epic FHIR metadata from {fhir_base_url}"
        logger.error(error_msg)
        raise NetworkError(error_msg)
        
    except requests.exceptions.ConnectionError as e:
        error_msg = f"Connection error retrieving Epic FHIR metadata: {str(e)}"
        logger.error(error_msg)
        raise NetworkError(error_msg)
        
    except requests.exceptions.HTTPError as e:
        error_msg = f"HTTP error retrieving Epic FHIR metadata: {e.response.status_code}"
        logger.error(error_msg)
        
        # Log security event for HTTP errors
        log_security_event(
            'fhir_metadata_http_error',
            {
                'fhir_server': fhir_base_url,
                'status_code': e.response.status_code,
                'error': str(e)
            },
            level='ERROR'
        )
        
        raise FHIRError(error_msg)
        
    except (ValueError, KeyError) as e:
        error_msg = f"Invalid Epic FHIR metadata format: {str(e)}"
        logger.error(error_msg)
        raise FHIRError(error_msg)
        
    except Exception as e:
        error_msg = f"Unexpected error retrieving Epic FHIR metadata: {str(e)}"
        logger.error(error_msg)
        raise FHIRError(error_msg)


def validate_epic_endpoints(metadata: EpicFHIRMetadata) -> List[str]:
    """
    Validate Epic-specific endpoints and configuration.
    
    Args:
        metadata: Parsed Epic FHIR metadata
        
    Returns:
        List of validation warnings/issues
    """
    issues = []
    
    # Check OAuth endpoints
    if not metadata.auth_endpoints.get('authorize'):
        issues.append("Missing OAuth2 authorization endpoint")
    
    if not metadata.auth_endpoints.get('token'):
        issues.append("Missing OAuth2 token endpoint")
    
    # Check essential FHIR resources for healthcare applications
    essential_resources = ['Patient', 'Observation', 'Condition', 'Procedure']
    
    for resource in essential_resources:
        if not metadata.supports_resource(resource):
            issues.append(f"Server does not support {resource} resource")
        else:
            interactions = metadata.get_resource_interactions(resource)
            if 'read' not in interactions:
                issues.append(f"{resource} resource does not support read operation")
    
    # Check FHIR version and provide compatibility notes
    if metadata.is_dstu2:
        issues.append("Server uses FHIR DSTU2 - some R4 features may not be available")
    elif metadata.fhir_version and not metadata.fhir_version.startswith('4.'):
        issues.append(f"FHIR version {metadata.fhir_version} may not be fully supported (R4 recommended)")
    
    return issues


def get_epic_smart_configuration(fhir_base_url: str) -> Dict[str, Any]:
    """
    Get Epic SMART on FHIR configuration for client registration.
    
    Args:
        fhir_base_url: Epic FHIR server base URL
        
    Returns:
        SMART configuration dictionary
    """
    try:
        metadata = get_epic_metadata(fhir_base_url)
        
        config = {
            'fhir_server': fhir_base_url,
            'fhir_version': metadata.fhir_version,
            'resource_type': metadata.resource_type,
            'is_dstu2': metadata.is_dstu2,
            'is_r4': metadata.is_r4,
            'authorization_endpoint': metadata.auth_endpoints.get('authorize'),
            'token_endpoint': metadata.auth_endpoints.get('token'),
            'revocation_endpoint': metadata.auth_endpoints.get('revoke'),
            'supported_resources': list(metadata.rest_capabilities.get('resources', {}).keys()),
            'has_smart_support': metadata.has_smart_capabilities()
        }
        
        # Add Epic-specific configuration
        if 'Patient' in config['supported_resources']:
            patient_search_params = metadata.get_search_parameters('Patient')
            config['patient_search_support'] = {
                'identifier': 'identifier' in patient_search_params,
                'name': 'name' in patient_search_params or 'family' in patient_search_params,
                'birthdate': 'birthdate' in patient_search_params
            }
        
        return config
        
    except Exception as e:
        logger.error(f"Failed to get Epic SMART configuration: {e}")
        return {
            'fhir_server': fhir_base_url,
            'error': str(e),
            'has_smart_support': False
        }