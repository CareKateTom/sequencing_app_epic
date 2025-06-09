"""
FHIR routes for Epic FHIR Integration application.

Healthcare-focused FHIR endpoints prioritizing security, compliance, and auditability.
Follows principle: "Secure and compliant, not enterprise-ready"
"""

from flask import Blueprint, request, session, render_template, jsonify, current_app, g
from typing import Dict, List, Optional, Any

from app.core.exceptions import (
    FHIRError, FHIRClientError, FHIRServerError, ResourceNotFoundError,
    InvalidSearchParametersError, AuthenticationError
)
from app.core.logging import get_logger, log_security_event, create_audit_log, log_epic_event
from app.auth.decorators import require_valid_token
from app.fhir.client import (
    create_fhir_client, search_patients_by_identifier, extract_patient_identifiers,
    extract_patient_demographics
)

logger = get_logger(__name__)


def create_fhir_blueprint() -> Blueprint:
    """
    Create and configure the FHIR blueprint.
    
    Returns:
        Configured Flask blueprint for FHIR routes
    """
    bp = Blueprint('fhir', __name__)
    
    # Patient-focused routes
    bp.add_url_rule('/patient/<patient_id>', 'get_patient', get_patient, methods=['GET'])
    bp.add_url_rule('/patient', 'get_test_patient', get_test_patient, methods=['GET'])
    bp.add_url_rule('/search', 'patient_search', patient_search, methods=['GET'])
    bp.add_url_rule('/search/page', 'search_page', search_page, methods=['GET'])
    
    # API testing and debugging
    bp.add_url_rule('/test', 'test_api', test_api, methods=['GET'])
    bp.add_url_rule('/connection', 'test_connection', test_connection, methods=['GET'])
    
    logger.info("FHIR blueprint created with all routes registered")
    return bp


@require_valid_token
def get_patient(patient_id: str, token: Dict[str, Any]):
    """
    Get a specific patient by FHIR ID.
    
    Args:
        patient_id: Patient FHIR ID from URL
        token: OAuth2 token from decorator
        
    Returns:
        Rendered patient template or JSON response
    """
    try:
        # Get FHIR server URL from session
        fhir_base_url = session.get('iss')
        if not fhir_base_url:
            raise AuthenticationError("No FHIR server URL found in session")
        
        # Create FHIR client
        client = create_fhir_client(fhir_base_url)
        epic_user_id = session.get('epic_user_id')
        
        # Get patient data
        patient_data = client.get_patient(patient_id, token['access_token'], epic_user_id)
        
        # Extract demographic information for display
        demographics = extract_patient_demographics(patient_data)
        identifiers = extract_patient_identifiers(patient_data)
        
        # Log Epic-specific event
        log_epic_event(
            'patient_retrieved',
            {
                'patient_id': patient_id,
                'epic_user_id': epic_user_id,
                'identifiers': identifiers
            }
        )
        
        logger.info(
            f"Patient retrieved successfully",
            extra={
                'patient_id': patient_id,
                'epic_user_id': epic_user_id
            }
        )
        
        # Return JSON for API requests, HTML for browser
        if request.is_json or request.args.get('format') == 'json':
            return jsonify({
                'patient': patient_data,
                'demographics': demographics,
                'identifiers': identifiers
            })
        
        return render_template(
            'fhir/patient.html',
            patient=patient_data,
            demographics=demographics,
            identifiers=identifiers
        )
        
    except ResourceNotFoundError as e:
        logger.warning(f"Patient not found: {patient_id}")
        
        if request.is_json:
            return jsonify({'error': f'Patient {patient_id} not found'}), 404
        
        return render_template(
            'fhir/error.html',
            error_title='Patient Not Found',
            error_message=f'Patient with ID "{patient_id}" was not found.',
            error_code=404
        ), 404
        
    except FHIRClientError as e:
        logger.error(f"FHIR client error retrieving patient {patient_id}: {e}")
        
        if request.is_json:
            return jsonify({'error': str(e)}), 400
        
        return render_template(
            'fhir/error.html',
            error_title='Patient Access Error',
            error_message=str(e),
            error_code=400
        ), 400
        
    except Exception as e:
        logger.error(f"Unexpected error retrieving patient {patient_id}: {e}")
        
        if request.is_json:
            return jsonify({'error': 'Internal server error'}), 500
        
        return render_template(
            'fhir/error.html',
            error_title='Unexpected Error',
            error_message='An unexpected error occurred while retrieving patient data.',
            error_code=500
        ), 500


@require_valid_token
def get_test_patient(token: Dict[str, Any]):
    """
    Get the default test patient (Camila Lopez) for demonstration.
    
    Args:
        token: OAuth2 token from decorator
        
    Returns:
        Redirect to specific patient or error response
    """
    # Camila Lopez's FHIR ID from Epic sandbox
    test_patient_id = "erXuFYUfucBZaryVksYEcMg3"
    
    logger.info(
        "Test patient requested",
        extra={
            'test_patient_id': test_patient_id,
            'epic_user_id': session.get('epic_user_id')
        }
    )
    
    # Redirect to the specific patient endpoint
    return get_patient(test_patient_id, token)


def search_page():
    """
    Render the patient search form page.
    
    Returns:
        Rendered search template
    """
    return render_template(
        'fhir/search.html',
        patients=None,
        searched=False
    )


@require_valid_token
def patient_search(token: Dict[str, Any]):
    """
    Search for patients using various criteria.
    
    Query Parameters:
        search_type (str): 'mrn', 'epi', 'name'
        search_value (str): Search value for mrn/epi
        family_name (str): Family name for name search
        given_name (str): Given name for name search
        
    Args:
        token: OAuth2 token from decorator
        
    Returns:
        Rendered search results or JSON response
    """
    try:
        # Get search parameters
        search_type = request.args.get('search_type', '').strip()
        search_value = request.args.get('search_value', '').strip()
        family_name = request.args.get('family_name', '').strip()
        given_name = request.args.get('given_name', '').strip()
        
        # Validate search parameters
        if not search_type:
            if request.is_json:
                return jsonify({'error': 'search_type parameter required'}), 400
            return render_template('fhir/search.html', patients=None, searched=False)
        
        # Get FHIR server URL
        fhir_base_url = session.get('iss')
        if not fhir_base_url:
            raise AuthenticationError("No FHIR server URL found in session")
        
        # Create FHIR client
        client = create_fhir_client(fhir_base_url)
        epic_user_id = session.get('epic_user_id')
        
        patients = []
        search_params = {}
        
        # Execute search based on type
        if search_type in ['mrn', 'epi'] and search_value:
            # Search by identifier
            identifier_system = 'MRN' if search_type == 'mrn' else 'EPI'
            search_params = {'type': search_type, 'value': search_value}
            
            patients = search_patients_by_identifier(
                client, identifier_system, search_value, 
                token['access_token'], epic_user_id
            )
            
        elif search_type == 'name' and (family_name or given_name):
            # Search by name
            from app.fhir.client import search_patients_by_name
            
            search_params = {
                'type': 'name',
                'family_name': family_name,
                'given_name': given_name
            }
            
            patients = search_patients_by_name(
                client, family_name, given_name,
                token['access_token'], epic_user_id
            )
            
        else:
            # Invalid search parameters
            if request.is_json:
                return jsonify({'error': 'Invalid search parameters'}), 400
            return render_template('fhir/search.html', patients=None, searched=False)
        
        # Enhance patient data for display
        enhanced_patients = []
        for patient in patients:
            try:
                demographics = extract_patient_demographics(patient)
                identifiers = extract_patient_identifiers(patient)
                
                enhanced_patient = {
                    'resource': patient,
                    'demographics': demographics,
                    'identifiers': identifiers
                }
                enhanced_patients.append(enhanced_patient)
                
            except Exception as e:
                logger.warning(f"Failed to enhance patient data: {e}")
                # Include patient anyway with minimal data
                enhanced_patients.append({
                    'resource': patient,
                    'demographics': {},
                    'identifiers': {'fhir_id': patient.get('id')}
                })
        
        # Log search completion
        log_epic_event(
            'patient_search_completed',
            {
                'search_params': search_params,
                'result_count': len(enhanced_patients),
                'epic_user_id': epic_user_id
            }
        )
        
        logger.info(
            f"Patient search completed",
            extra={
                'search_type': search_type,
                'result_count': len(enhanced_patients),
                'epic_user_id': epic_user_id
            }
        )
        
        # Return results
        if request.is_json:
            return jsonify({
                'patients': enhanced_patients,
                'search_params': search_params,
                'result_count': len(enhanced_patients)
            })
        
        return render_template(
            'fhir/search.html',
            patients=enhanced_patients,
            searched=True,
            search_params=search_params
        )
        
    except InvalidSearchParametersError as e:
        logger.warning(f"Invalid search parameters: {e}")
        
        if request.is_json:
            return jsonify({'error': 'Invalid search parameters'}), 400
        
        return render_template(
            'fhir/search.html',
            patients=None,
            searched=True,
            error_message="Invalid search parameters provided"
        )
        
    except FHIRClientError as e:
        logger.error(f"FHIR client error during search: {e}")
        
        if request.is_json:
            return jsonify({'error': str(e)}), 400
        
        return render_template(
            'fhir/search.html',
            patients=None,
            searched=True,
            error_message=str(e)
        )
        
    except Exception as e:
        logger.error(f"Unexpected error during patient search: {e}")
        
        if request.is_json:
            return jsonify({'error': 'Search failed'}), 500
        
        return render_template(
            'fhir/search.html',
            patients=None,
            searched=True,
            error_message="An unexpected error occurred during search"
        )


@require_valid_token
def test_api(token: Dict[str, Any]):
    """
    Test arbitrary FHIR API endpoints for debugging and exploration.
    
    Query Parameters:
        endpoint (str): FHIR endpoint path to test
        
    Args:
        token: OAuth2 token from decorator
        
    Returns:
        Rendered API test results or JSON response
    """
    endpoint = request.args.get('endpoint', '').strip()
    
    if not endpoint:
        return render_template('fhir/test_api.html', response=None, endpoint='')
    
    try:
        # Get FHIR server URL
        fhir_base_url = session.get('iss')
        if not fhir_base_url:
            raise AuthenticationError("No FHIR server URL found in session")
        
        # Create FHIR client and build URL
        client = create_fhir_client(fhir_base_url)
        epic_user_id = session.get('epic_user_id')
        
        # Remove leading slash if present
        endpoint = endpoint.lstrip('/')
        full_url = f"{fhir_base_url}/{endpoint}"
        
        # Log API test attempt
        log_security_event(
            'fhir_api_test',
            {
                'endpoint': endpoint,
                'full_url': full_url,
                'epic_user_id': epic_user_id
            }
        )
        
        # Make the request
        headers = client._build_headers(token['access_token'])
        response = client.session.get(full_url, headers=headers, timeout=client.timeout)
        
        # Build response info for display
        response_info = {
            'status_code': response.status_code,
            'status_text': response.reason,
            'headers': dict(response.headers),
            'url': response.url,
            'endpoint': endpoint,
            'success': response.ok
        }
        
        # Add response body
        try:
            if response.headers.get('content-type', '').startswith('application/json'):
                response_info['body'] = response.json()
                response_info['body_type'] = 'json'
            else:
                response_info['body'] = response.text
                response_info['body_type'] = 'text'
        except Exception as e:
            response_info['body'] = f"Failed to parse response: {str(e)}"
            response_info['body_type'] = 'error'
        
        # Add token info for debugging
        response_info['token_info'] = {
            'scope': token.get('scope'),
            'token_type': token.get('token_type'),
            'epic_user_id': epic_user_id
        }
        
        logger.info(
            f"API test completed",
            extra={
                'endpoint': endpoint,
                'status_code': response.status_code,
                'epic_user_id': epic_user_id
            }
        )
        
        if request.is_json:
            return jsonify(response_info)
        
        return render_template('fhir/test_api.html', response=response_info, endpoint=endpoint)
        
    except Exception as e:
        logger.error(f"API test failed for endpoint '{endpoint}': {e}")
        
        error_info = {
            'error_type': type(e).__name__,
            'error_message': str(e),
            'endpoint': endpoint,
            'success': False
        }
        
        if request.is_json:
            return jsonify(error_info), 500
        
        return render_template('fhir/test_api.html', error=error_info, endpoint=endpoint)


@require_valid_token
def test_connection(token: Dict[str, Any]):
    """
    Test FHIR server connection and retrieve capability statement.
    
    Args:
        token: OAuth2 token from decorator
        
    Returns:
        JSON response with connection status and server info
    """
    try:
        # Get FHIR server URL
        fhir_base_url = session.get('iss')
        if not fhir_base_url:
            raise AuthenticationError("No FHIR server URL found in session")
        
        # Create FHIR client and test connection
        client = create_fhir_client(fhir_base_url)
        connection_result = client.test_connection(token['access_token'])
        
        # Add session context
        connection_result['session_info'] = {
            'fhir_server': fhir_base_url,
            'epic_user_id': session.get('epic_user_id'),
            'launch_type': session.get('launch_type')
        }
        
        # Log connection test
        log_epic_event(
            'fhir_connection_tested',
            {
                'status': connection_result['status'],
                'fhir_server': fhir_base_url,
                'epic_user_id': session.get('epic_user_id')
            }
        )
        
        logger.info(
            f"FHIR connection test completed",
            extra={
                'status': connection_result['status'],
                'fhir_server': fhir_base_url
            }
        )
        
        return jsonify(connection_result)
        
    except Exception as e:
        logger.error(f"Connection test failed: {e}")
        
        error_result = {
            'status': 'error',
            'error': str(e),
            'session_info': {
                'fhir_server': session.get('iss'),
                'epic_user_id': session.get('epic_user_id')
            }
        }
        
        return jsonify(error_result), 500


# Helper functions for route processing
def _validate_patient_access(patient_id: str, epic_user_id: Optional[str]) -> None:
    """
    Validate that user has appropriate access to patient data.
    
    Args:
        patient_id: Patient FHIR ID
        epic_user_id: Epic user ID
        
    Note: 
        This is a placeholder for more sophisticated access control.
        In a real implementation, you would check Epic user permissions,
        patient consent, break-glass access, etc.
    """
    # Log access attempt for audit trail
    create_audit_log(
        action='access_validation',
        resource=f'Patient/{patient_id}',
        user_id=epic_user_id,
        details={
            'patient_id': patient_id,
            'validation_result': 'allowed'  # Simplified for this implementation
        }
    )


def _extract_search_criteria(request_args: Dict[str, str]) -> Dict[str, Any]:
    """
    Extract and validate search criteria from request arguments.
    
    Args:
        request_args: Flask request arguments
        
    Returns:
        Validated search criteria
        
    Raises:
        InvalidSearchParametersError: If criteria are invalid
    """
    search_type = request_args.get('search_type', '').strip().lower()
    
    if search_type not in ['mrn', 'epi', 'name']:
        raise InvalidSearchParametersError({'search_type': search_type})
    
    criteria = {'search_type': search_type}
    
    if search_type in ['mrn', 'epi']:
        search_value = request_args.get('search_value', '').strip()
        if not search_value:
            raise InvalidSearchParametersError({'search_value': 'required'})
        criteria['search_value'] = search_value
        
    elif search_type == 'name':
        family_name = request_args.get('family_name', '').strip()
        given_name = request_args.get('given_name', '').strip()
        
        if not family_name and not given_name:
            raise InvalidSearchParametersError({'name': 'family_name or given_name required'})
        
        if family_name:
            criteria['family_name'] = family_name
        if given_name:
            criteria['given_name'] = given_name
    
    return criteria


def _format_patient_for_display(patient: Dict[str, Any]) -> Dict[str, Any]:
    """
    Format patient resource for consistent display across templates.
    
    Args:
        patient: Patient FHIR resource
        
    Returns:
        Formatted patient data for templates
    """
    try:
        demographics = extract_patient_demographics(patient)
        identifiers = extract_patient_identifiers(patient)
        
        # Build display name
        display_name = demographics.get('full_name', 'Unknown Patient')
        
        # Format address for display
        address_info = demographics.get('address', {})
        address_lines = address_info.get('line', [])
        address_display = ', '.join(filter(None, [
            ' '.join(address_lines),
            address_info.get('city'),
            address_info.get('state'),
            address_info.get('postal_code')
        ]))
        
        return {
            'fhir_resource': patient,
            'display_name': display_name,
            'identifiers': identifiers,
            'demographics': demographics,
            'address_display': address_display,
            'primary_phone': demographics.get('phone_numbers', [{}])[0].get('value'),
            'primary_email': demographics.get('email_addresses', [{}])[0].get('value')
        }
        
    except Exception as e:
        logger.warning(f"Failed to format patient for display: {e}")
        
        # Return minimal safe format
        return {
            'fhir_resource': patient,
            'display_name': 'Unknown Patient',
            'identifiers': {'fhir_id': patient.get('id')},
            'demographics': {},
            'address_display': '',
            'primary_phone': None,
            'primary_email': None
        }


def _log_patient_access(action: str, patient_id: str, epic_user_id: Optional[str], 
                       additional_details: Optional[Dict[str, Any]] = None) -> None:
    """
    Log patient data access for HIPAA compliance and audit trails.
    
    Args:
        action: Type of access (read, search, etc.)
        patient_id: Patient identifier
        epic_user_id: Epic user ID
        additional_details: Additional context for the log
    """
    details = {
        'patient_id': patient_id,
        'access_type': 'patient_data',
        **(additional_details or {})
    }
    
    create_audit_log(
        action=action,
        resource=f'Patient/{patient_id}',
        user_id=epic_user_id,
        details=details
    )
    
    # Also log as security event for monitoring
    log_security_event(
        'patient_data_access',
        {
            'action': action,
            'patient_id': patient_id,
            'epic_user_id': epic_user_id,
            **details
        }
    )