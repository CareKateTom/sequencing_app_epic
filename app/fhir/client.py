"""
FHIR API client for Epic FHIR Integration application.

Healthcare-focused FHIR client prioritizing security and compliance.
Follows principle: "Secure and compliant, not enterprise-ready"
"""

from typing import Dict, List, Optional, Any
import requests

from app.core.exceptions import FHIRError, AuthenticationError, handle_requests_error
from app.core.logging import get_logger, log_security_event, create_audit_log

logger = get_logger(__name__)


class FHIRClient:
    """
    Simple FHIR client for Epic integration with security focus.
    
    Features:
    - Epic-specific authentication and error handling
    - Security logging for all FHIR operations
    - Audit logging for patient data access
    - Basic error handling without over-engineering
    """
    
    def __init__(self, base_url: str, timeout: int = 30):
        """Initialize FHIR client."""
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        logger.info(f"FHIR client initialized for: {self.base_url}")
    
    def get_patient(
        self, 
        patient_id: str, 
        token: str,
        epic_user_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Get a specific patient by FHIR ID."""
        url = f"{self.base_url}/Patient/{patient_id}"
        
        # Log access attempt for security monitoring
        log_security_event(
            'fhir_patient_access',
            {
                'patient_id': patient_id,
                'epic_user_id': epic_user_id,
                'url': url
            }
        )
        
        response = self._make_request('GET', url, token)
        patient_data = response.json()
        
        # Create audit log for patient data access
        create_audit_log(
            action='read',
            resource=f"Patient/{patient_id}",
            user_id=epic_user_id,
            details={'patient_id': patient_id, 'success': True}
        )
        
        logger.info(f"Retrieved patient: {patient_id}")
        return patient_data
    
    def search_patients(
        self,
        search_params: Dict[str, str],
        token: str,
        epic_user_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Search for patients with parameters."""
        if not search_params:
            raise FHIRError("Search parameters required")
        
        # Add count limit for security
        params = search_params.copy()
        params['_count'] = '50'
        
        url = f"{self.base_url}/Patient"
        
        # Log search attempt
        log_security_event(
            'fhir_patient_search',
            {
                'search_params': search_params,
                'epic_user_id': epic_user_id
            }
        )
        
        response = self._make_request('GET', url, token, params=params)
        bundle_data = response.json()
        
        # Extract patients from bundle
        patients = []
        for entry in bundle_data.get('entry', []):
            resource = entry.get('resource', {})
            if resource.get('resourceType') == 'Patient':
                patients.append(resource)
        
        # Create audit log
        create_audit_log(
            action='search',
            resource='Patient',
            user_id=epic_user_id,
            details={
                'search_params': search_params,
                'result_count': len(patients),
                'success': True
            }
        )
        
        logger.info(f"Patient search completed: {len(patients)} results")
        return patients
    
    def get_resource(
        self,
        resource_type: str,
        resource_id: str,
        token: str,
        epic_user_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Get any FHIR resource by type and ID."""
        url = f"{self.base_url}/{resource_type}/{resource_id}"
        
        log_security_event(
            'fhir_resource_access',
            {
                'resource_type': resource_type,
                'resource_id': resource_id,
                'epic_user_id': epic_user_id
            }
        )
        
        response = self._make_request('GET', url, token)
        resource_data = response.json()
        
        # Basic validation - Epic does the heavy lifting
        if resource_data.get('resourceType') != resource_type:
            raise FHIRError(f"Expected {resource_type}, got {resource_data.get('resourceType')}")
        
        create_audit_log(
            action='read',
            resource=f"{resource_type}/{resource_id}",
            user_id=epic_user_id
        )
        
        return resource_data
    
    def test_connection(self, token: str) -> Dict[str, Any]:
        """Test FHIR server connection."""
        url = f"{self.base_url}/metadata"
        
        try:
            response = self._make_request('GET', url, token)
            metadata = response.json()
            
            return {
                'status': 'connected',
                'fhir_version': metadata.get('fhirVersion'),
                'software': metadata.get('software', {})
            }
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e)
            }
    
    def _make_request(
        self,
        method: str,
        url: str,
        token: str,
        params: Optional[Dict[str, str]] = None,
        data: Optional[Dict[str, Any]] = None
    ) -> requests.Response:
        """Make HTTP request to Epic FHIR API."""
        headers = {
            'Authorization': f'Bearer {token}',
            'Accept': 'application/json+fhir',
            'Content-Type': 'application/json+fhir'
        }
        
        try:
            # Simple request - no complex retry logic
            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                params=params,
                json=data,
                timeout=self.timeout
            )
            
            # Handle Epic-specific errors
            if not response.ok:
                self._handle_error_response(response)
            
            return response
            
        except requests.RequestException as e:
            error_msg = f"FHIR API request failed: {str(e)}"
            logger.error(error_msg)
            raise FHIRError(error_msg)
    
    def _handle_error_response(self, response: requests.Response) -> None:
        """Handle Epic FHIR error responses."""
        status_code = response.status_code
        
        # Log security events for auth failures
        if status_code == 401:
            log_security_event(
                'fhir_auth_failure',
                {'status_code': status_code, 'url': response.url},
                level='ERROR'
            )
            raise AuthenticationError("FHIR authentication failed")
        
        elif status_code == 403:
            log_security_event(
                'fhir_access_denied',
                {'status_code': status_code, 'url': response.url},
                level='ERROR'
            )
            raise AuthenticationError("FHIR access forbidden")
        
        # Let Epic error details through - they're helpful for debugging
        try:
            error_body = response.json()
            error_msg = self._extract_epic_error_message(error_body)
        except:
            error_msg = f"HTTP {status_code}: {response.reason}"
        
        logger.error(f"FHIR API error: {error_msg}")
        raise FHIRError(error_msg)
    
    def _extract_epic_error_message(self, error_body: Dict[str, Any]) -> str:
        """Extract meaningful error message from Epic response."""
        # Epic FHIR OperationOutcome format
        if error_body.get('resourceType') == 'OperationOutcome':
            issues = error_body.get('issue', [])
            if issues:
                return issues[0].get('details', {}).get('text', 'Unknown Epic error')
        
        # OAuth error format
        if 'error' in error_body:
            error_msg = error_body['error']
            if 'error_description' in error_body:
                error_msg += f": {error_body['error_description']}"
            return error_msg
        
        return str(error_body)


# Convenience functions for common operations
def create_fhir_client(base_url: str) -> FHIRClient:
    """Create FHIR client instance."""
    return FHIRClient(base_url)


def search_patients_by_identifier(
    client: FHIRClient,
    identifier_system: str,
    identifier_value: str,
    token: str,
    epic_user_id: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Search patients by identifier (MRN, EPI, etc.)."""
    search_params = {
        'identifier': f'{identifier_system}|{identifier_value}'
    }
    return client.search_patients(search_params, token, epic_user_id)


def extract_patient_identifiers(patient: Dict[str, Any]) -> Dict[str, str]:
    """Extract common patient identifiers."""
    identifiers = {}
    
    # FHIR ID
    if patient.get('id'):
        identifiers['fhir_id'] = patient['id']
    
    # Extract from identifier array
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
    """Extract basic demographic information."""
    demographics = {}
    
    # Name
    names = patient.get('name', [])
    if names:
        primary_name = names[0]
        demographics['family_name'] = primary_name.get('family')
        demographics['given_names'] = primary_name.get('given', [])
        demographics['full_name'] = ' '.join(
            demographics['given_names'] + [demographics['family_name']]
        ).strip()
    
    # Basic demographics
    demographics['gender'] = patient.get('gender')
    demographics['birth_date'] = patient.get('birthDate')
    
    # Address (first address only)
    addresses = patient.get('address', [])
    if addresses:
        addr = addresses[0]
        demographics['address'] = {
            'line': addr.get('line', []),
            'city': addr.get('city'),
            'state': addr.get('state'),
            'postal_code': addr.get('postalCode')
        }
    
    return demographics