"""
FHIR API client for Epic FHIR Integration application.

Healthcare-focused FHIR client prioritizing security, compliance, and auditability.
Follows principle: "Secure and compliant, not enterprise-ready"
"""

import json
from typing import Dict, List, Optional, Any, Union
from urllib.parse import urljoin, urlencode
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from app.core.exceptions import (
    FHIRError, FHIRClientError, FHIRServerError, ResourceNotFoundError,
    InvalidSearchParametersError, handle_requests_error
)
from app.core.logging import get_logger, log_security_event, create_audit_log, log_performance

logger = get_logger(__name__)


class FHIRClient:
    """
    Simple FHIR client for Epic integration with security and compliance focus.
    
    Features:
    - Epic-specific authentication and error handling
    - Security logging for all FHIR operations
    - Audit logging for patient data access
    - Simple retry logic for network issues
    - Request/response validation
    """
    
    def __init__(self, base_url: str, timeout: int = 30):
        """
        Initialize FHIR client.
        
        Args:
            base_url: Epic FHIR server base URL
            timeout: Request timeout in seconds
        """
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        
        # Setup session with basic retry logic
        self.session = requests.Session()
        retry_strategy = Retry(
            total=2,  # Simple retry, not enterprise-level
            backoff_factor=1,
            status_forcelist=[500, 502, 503, 504],
            allowed_methods=["GET", "POST"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        logger.info(f"FHIR client initialized for: {self.base_url}")
    
    def get_resource(
        self, 
        resource_type: str, 
        resource_id: str, 
        token: str,
        epic_user_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get a specific FHIR resource by ID.
        
        Args:
            resource_type: FHIR resource type (e.g., 'Patient', 'Observation')
            resource_id: Resource ID
            token: OAuth2 access token
            epic_user_id: Epic user ID for audit logging
            
        Returns:
            FHIR resource as dictionary
            
        Raises:
            ResourceNotFoundError: If resource doesn't exist
            FHIRClientError: For 4xx client errors
            FHIRServerError: For 5xx server errors
        """
        url = f"{self.base_url}/{resource_type}/{resource_id}"
        
        with log_performance(f"fhir_get_{resource_type.lower()}", logger):
            try:
                headers = self._build_headers(token)
                
                # Log the access attempt for security monitoring
                log_security_event(
                    'fhir_resource_access',
                    {
                        'resource_type': resource_type,
                        'resource_id': resource_id,
                        'epic_user_id': epic_user_id,
                        'url': url
                    }
                )
                
                response = self.session.get(url, headers=headers, timeout=self.timeout)
                
                # Handle specific error cases
                if response.status_code == 404:
                    raise ResourceNotFoundError(resource_type, resource_id)
                
                if not response.ok:
                    raise handle_requests_error(response, {
                        'resource_type': resource_type,
                        'resource_id': resource_id
                    })
                
                resource_data = response.json()
                
                # Validate FHIR resource structure
                self._validate_fhir_resource(resource_data, resource_type)
                
                # Create audit log for patient data access
                create_audit_log(
                    action='read',
                    resource=f"{resource_type}/{resource_id}",
                    user_id=epic_user_id,
                    details={
                        'resource_type': resource_type,
                        'success': True
                    }
                )
                
                logger.info(
                    f"Retrieved {resource_type} resource",
                    extra={
                        'resource_type': resource_type,
                        'resource_id': resource_id,
                        'epic_user_id': epic_user_id
                    }
                )
                
                return resource_data
                
            except (ResourceNotFoundError, FHIRClientError, FHIRServerError):
                # Re-raise FHIR-specific errors
                raise
            except requests.RequestException as e:
                error_msg = f"Network error retrieving {resource_type}/{resource_id}: {str(e)}"
                logger.error(error_msg)
                raise FHIRError(error_msg, original_error=e)
            except Exception as e:
                error_msg = f"Unexpected error retrieving {resource_type}/{resource_id}: {str(e)}"
                logger.error(error_msg)
                raise FHIRError(error_msg, original_error=e)
    
    def search_resources(
        self,
        resource_type: str,
        search_params: Dict[str, str],
        token: str,
        epic_user_id: Optional[str] = None,
        max_results: int = 50
    ) -> Dict[str, Any]:
        """
        Search for FHIR resources with parameters.
        
        Args:
            resource_type: FHIR resource type to search
            search_params: Search parameters as key-value pairs
            token: OAuth2 access token
            epic_user_id: Epic user ID for audit logging
            max_results: Maximum number of results to return
            
        Returns:
            FHIR Bundle containing search results
            
        Raises:
            InvalidSearchParametersError: If search parameters are invalid
            FHIRClientError: For 4xx client errors
            FHIRServerError: For 5xx server errors
        """
        # Validate search parameters
        if not search_params:
            raise InvalidSearchParametersError({})
        
        # Add count parameter to limit results
        search_params = search_params.copy()
        search_params['_count'] = str(max_results)
        
        url = f"{self.base_url}/{resource_type}"
        query_string = urlencode(search_params)
        full_url = f"{url}?{query_string}"
        
        with log_performance(f"fhir_search_{resource_type.lower()}", logger):
            try:
                headers = self._build_headers(token)
                
                # Log search attempt for security monitoring
                log_security_event(
                    'fhir_resource_search',
                    {
                        'resource_type': resource_type,
                        'search_params': search_params,
                        'epic_user_id': epic_user_id
                    }
                )
                
                response = self.session.get(full_url, headers=headers, timeout=self.timeout)
                
                if response.status_code == 400:
                    raise InvalidSearchParametersError(search_params)
                
                if not response.ok:
                    raise handle_requests_error(response, {
                        'resource_type': resource_type,
                        'search_params': search_params
                    })
                
                bundle_data = response.json()
                
                # Validate Bundle structure
                if bundle_data.get('resourceType') != 'Bundle':
                    raise FHIRError(f"Expected Bundle, got {bundle_data.get('resourceType')}")
                
                result_count = len(bundle_data.get('entry', []))
                
                # Create audit log for search operation
                create_audit_log(
                    action='search',
                    resource=resource_type,
                    user_id=epic_user_id,
                    details={
                        'resource_type': resource_type,
                        'search_params': search_params,
                        'result_count': result_count,
                        'success': True
                    }
                )
                
                logger.info(
                    f"Search completed for {resource_type}",
                    extra={
                        'resource_type': resource_type,
                        'result_count': result_count,
                        'epic_user_id': epic_user_id
                    }
                )
                
                return bundle_data
                
            except (InvalidSearchParametersError, FHIRClientError, FHIRServerError):
                # Re-raise FHIR-specific errors
                raise
            except requests.RequestException as e:
                error_msg = f"Network error searching {resource_type}: {str(e)}"
                logger.error(error_msg)
                raise FHIRError(error_msg, original_error=e)
            except Exception as e:
                error_msg = f"Unexpected error searching {resource_type}: {str(e)}"
                logger.error(error_msg)
                raise FHIRError(error_msg, original_error=e)
    
    def search_patients(
        self,
        search_params: Dict[str, str],
        token: str,
        epic_user_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Search for patients and return just the Patient resources.
        
        Args:
            search_params: Search parameters (identifier, name, etc.)
            token: OAuth2 access token
            epic_user_id: Epic user ID for audit logging
            
        Returns:
            List of Patient resources
        """
        bundle = self.search_resources('Patient', search_params, token, epic_user_id)
        
        patients = []
        for entry in bundle.get('entry', []):
            resource = entry.get('resource', {})
            if resource.get('resourceType') == 'Patient':
                patients.append(resource)
        
        return patients
    
    def get_patient(
        self,
        patient_id: str,
        token: str,
        epic_user_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get a specific patient by ID.
        
        Args:
            patient_id: Patient FHIR ID
            token: OAuth2 access token
            epic_user_id: Epic user ID for audit logging
            
        Returns:
            Patient resource
        """
        return self.get_resource('Patient', patient_id, token, epic_user_id)
    
    def test_connection(self, token: str) -> Dict[str, Any]:
        """
        Test FHIR server connection with capability statement.
        
        Args:
            token: OAuth2 access token
            
        Returns:
            Capability statement or connection status
        """
        url = f"{self.base_url}/metadata"
        
        try:
            headers = self._build_headers(token)
            response = self.session.get(url, headers=headers, timeout=self.timeout)
            
            if response.ok:
                metadata = response.json()
                return {
                    'status': 'connected',
                    'fhir_version': metadata.get('fhirVersion'),
                    'software': metadata.get('software', {}),
                    'implementation': metadata.get('implementation', {})
                }
            else:
                return {
                    'status': 'error',
                    'status_code': response.status_code,
                    'error': response.text
                }
                
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e)
            }
    
    def _build_headers(self, token: str) -> Dict[str, str]:
        """Build standard FHIR request headers."""
        return {
            'Authorization': f'Bearer {token}',
            'Accept': 'application/json+fhir',
            'Content-Type': 'application/json+fhir'
        }
    
    def _validate_fhir_resource(self, resource: Dict[str, Any], expected_type: str) -> None:
        """
        Basic validation of FHIR resource structure.
        
        Args:
            resource: FHIR resource to validate
            expected_type: Expected resource type
            
        Raises:
            FHIRError: If resource is invalid
        """
        if not isinstance(resource, dict):
            raise FHIRError("Resource must be a dictionary")
        
        resource_type = resource.get('resourceType')
        if not resource_type:
            raise FHIRError("Resource missing resourceType")
        
        if resource_type != expected_type:
            raise FHIRError(f"Expected {expected_type}, got {resource_type}")
        
        if not resource.get('id'):
            logger.warning(f"{expected_type} resource missing ID field")


# Convenience functions for common operations
def create_fhir_client(base_url: str, timeout: int = 30) -> FHIRClient:
    """
    Create and return a configured FHIR client.
    
    Args:
        base_url: Epic FHIR server base URL
        timeout: Request timeout in seconds
        
    Returns:
        Configured FHIRClient instance
    """
    return FHIRClient(base_url, timeout)


def search_patients_by_identifier(
    client: FHIRClient,
    identifier_system: str,
    identifier_value: str,
    token: str,
    epic_user_id: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Search for patients by identifier (MRN, EPI, etc.).
    
    Args:
        client: FHIR client instance
        identifier_system: Identifier system (e.g., 'MRN', 'EPI')
        identifier_value: Identifier value
        token: OAuth2 access token
        epic_user_id: Epic user ID for audit logging
        
    Returns:
        List of matching Patient resources
    """
    search_params = {
        'identifier': f'{identifier_system}|{identifier_value}'
    }
    
    return client.search_patients(search_params, token, epic_user_id)


def search_patients_by_name(
    client: FHIRClient,
    family_name: Optional[str] = None,
    given_name: Optional[str] = None,
    token: str = None,
    epic_user_id: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Search for patients by name components.
    
    Args:
        client: FHIR client instance
        family_name: Patient's family/last name
        given_name: Patient's given/first name
        token: OAuth2 access token
        epic_user_id: Epic user ID for audit logging
        
    Returns:
        List of matching Patient resources
    """
    search_params = {}
    
    if family_name:
        search_params['family'] = family_name
    if given_name:
        search_params['given'] = given_name
    
    if not search_params:
        raise InvalidSearchParametersError({})
    
    return client.search_patients(search_params, token, epic_user_id)


def extract_patient_identifiers(patient: Dict[str, Any]) -> Dict[str, str]:
    """
    Extract common patient identifiers from Patient resource.
    
    Args:
        patient: Patient FHIR resource
        
    Returns:
        Dictionary of extracted identifiers
    """
    identifiers = {}
    
    # Extract FHIR ID
    if patient.get('id'):
        identifiers['fhir_id'] = patient['id']
    
    # Extract identifiers from identifier array
    for identifier in patient.get('identifier', []):
        system = identifier.get('system', '')
        value = identifier.get('value', '')
        
        if not value:
            continue
        
        # Epic MRN
        if 'urn:oid:1.2.840.114350.1.13.0.1.7.5.737384.14' in system:
            identifiers['mrn'] = value
        # Epic EPI
        elif 'http://open.epic.com/FHIR/StructureDefinition/patient-fhir-id' in system:
            identifiers['epi'] = value
        # SSN
        elif 'http://hl7.org/fhir/sid/us-ssn' in system:
            identifiers['ssn'] = value
    
    return identifiers


def extract_patient_demographics(patient: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract demographic information from Patient resource.
    
    Args:
        patient: Patient FHIR resource
        
    Returns:
        Dictionary of demographic data
    """
    demographics = {}
    
    # Extract name
    names = patient.get('name', [])
    if names:
        primary_name = names[0]  # Use first name entry
        demographics['family_name'] = primary_name.get('family')
        demographics['given_names'] = primary_name.get('given', [])
        demographics['full_name'] = ' '.join(
            demographics['given_names'] + [demographics['family_name']]
        ).strip()
    
    # Extract basic demographics
    demographics['gender'] = patient.get('gender')
    demographics['birth_date'] = patient.get('birthDate')
    
    # Extract address
    addresses = patient.get('address', [])
    if addresses:
        primary_address = addresses[0]
        demographics['address'] = {
            'line': primary_address.get('line', []),
            'city': primary_address.get('city'),
            'state': primary_address.get('state'),
            'postal_code': primary_address.get('postalCode'),
            'country': primary_address.get('country')
        }
    
    # Extract telecom
    telecoms = patient.get('telecom', [])
    demographics['phone_numbers'] = []
    demographics['email_addresses'] = []
    
    for telecom in telecoms:
        if telecom.get('system') == 'phone':
            demographics['phone_numbers'].append({
                'value': telecom.get('value'),
                'use': telecom.get('use')
            })
        elif telecom.get('system') == 'email':
            demographics['email_addresses'].append({
                'value': telecom.get('value'),
                'use': telecom.get('use')
            })
    
    return demographics