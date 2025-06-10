"""
HL7 routes for Epic FHIR Integration application.

Healthcare-focused HL7 endpoints prioritizing security, compliance, and auditability.
Handles Epic bidirectional coding interface messaging.
"""

from flask import Blueprint, request, session, render_template, jsonify, redirect, url_for, g
from typing import Dict, Any, Optional

from app.core.exceptions import HL7Error, HL7ParseError, AuthenticationError
from app.core.logging import get_logger, log_security_event, create_audit_log, log_epic_event
from app.auth.decorators import require_valid_token, require_epic_endpoint
from app.hl7.parser import EpicHL7Parser, parse_hl7_message, validate_hl7_message
import requests

logger = get_logger(__name__)


def create_hl7_blueprint() -> Blueprint:
    """
    Create and configure the HL7 blueprint.
    
    Returns:
        Configured Flask blueprint for HL7 routes
    """
    bp = Blueprint('hl7', __name__)
    
    # HL7 messaging routes - FIXED route registration
    bp.add_url_rule('/message/get', 'test_get_message', test_get_message, methods=['GET'])
    bp.add_url_rule('/message/send', 'test_set_message', test_set_message, methods=['GET', 'POST'])
    bp.add_url_rule('/parser/test', 'test_parser', test_parser, methods=['GET', 'POST'])
    bp.add_url_rule('/menu', 'message_menu', message_menu, methods=['GET'])
    
    # API endpoints - THIS WAS MISSING
    bp.add_url_rule('/api/parse', 'api_parse_hl7', api_parse_hl7, methods=['POST'])
    
    logger.info("HL7 blueprint created with all routes registered")
    return bp


@require_valid_token
@require_epic_endpoint('getMessage')
def test_get_message(token: Dict[str, Any]):
    """
    Test the Epic GetEncoderMessage endpoint with parsing.
    
    Retrieves HL7 messages from Epic's bidirectional coding interface.
    
    Args:
        token: OAuth2 token from decorator
        
    Returns:
        Rendered HL7 message analysis page or JSON response
    """
    try:
        # Get getMessage URL from request context (set by decorator)
        get_message_url = g.get_message_url
        epic_user_id = session.get('epic_user_id')
        
        # Set up headers
        headers = {
            'Authorization': f"Bearer {token['access_token']}",
            'Accept': 'application/json'
        }
        
        # Log the attempt
        log_epic_event(
            'hl7_get_message_attempt',
            {
                'epic_user_id': epic_user_id,
                'endpoint': get_message_url
            }
        )
        
        # Make request to Epic
        response = requests.get(get_message_url, headers=headers, timeout=30)
        response.raise_for_status()
        
        # Parse Epic response
        message_data = response.json()
        
        # Check response format
        if 'Message' in message_data and message_data['Message']:
            hl7_message = message_data['Message']
            
            # Parse HL7 message
            try:
                parsed_data = parse_hl7_message(hl7_message)
                
                # Get PSI-ready data
                parser = EpicHL7Parser()
                psi_data = parser.get_psi_ready_dataframes(parsed_data)
                
                # Split message into segments for display
                segments = hl7_message.split('\r\n') if '\r\n' in hl7_message else hl7_message.split('\n')
                
                # Create audit log
                create_audit_log(
                    action='hl7_message_retrieved',
                    resource='hl7_message',
                    user_id=epic_user_id,
                    details={
                        'message_type': parsed_data.get('message_info', {}).get('message_type'),
                        'patient_id': parsed_data.get('patient', {}).get('patient_id'),
                        'diagnoses_count': len(parsed_data.get('diagnoses', [])),
                        'procedures_count': len(parsed_data.get('procedures', []))
                    }
                )
                
                logger.info("HL7 message retrieved and parsed successfully")
                
                if request.is_json:
                    return jsonify({
                        'message': hl7_message,
                        'parsed_data': parsed_data,
                        'psi_data': psi_data
                    })
                
                return render_template(
                    'hl7/message_analysis.html',
                    message=hl7_message,
                    segments=segments,
                    raw_response=message_data,
                    parsed_data=parsed_data,
                    psi_data=psi_data
                )
                
            except HL7ParseError as e:
                logger.error(f"HL7 parsing failed: {e}")
                
                if request.is_json:
                    return jsonify({'error': f'HL7 parsing failed: {str(e)}'}), 400
                
                return render_template(
                    'hl7/message_analysis.html',
                    message=hl7_message,
                    segments=hl7_message.split('\n'),
                    raw_response=message_data,
                    parsing_error=str(e)
                ), 400
        
        elif 'Error' in message_data and message_data['Error']:
            error_data = message_data['Error']
            logger.warning(f"Epic returned error: {error_data}")
            
            if request.is_json:
                return jsonify({'error': f"Epic error: {error_data}"}), 400
            
            return render_template(
                'hl7/error.html',
                error_title='Epic HL7 Error',
                error_message=f"Epic returned an error: {error_data}",
                error_code=400
            ), 400
        
        else:
            logger.warning("Unexpected Epic response format")
            
            if request.is_json:
                return jsonify({'error': 'Unexpected response format from Epic'}), 500
            
            return render_template(
                'hl7/error.html',
                error_title='Response Format Error',
                error_message='Unexpected response format from Epic getMessage endpoint',
                error_code=500
            ), 500
            
    except requests.RequestException as e:
        logger.error(f"Request failed to Epic getMessage endpoint: {e}")
        
        if request.is_json:
            return jsonify({'error': f'Request failed: {str(e)}'}), 500
        
        return render_template(
            'hl7/error.html',
            error_title='Epic Request Failed',
            error_message=f'Failed to retrieve message from Epic: {str(e)}',
            error_code=500
        ), 500
    
    except Exception as e:
        logger.error(f"Unexpected error in get_message: {e}")
        
        if request.is_json:
            return jsonify({'error': 'Internal server error'}), 500
        
        return render_template(
            'hl7/error.html',
            error_title='Unexpected Error',
            error_message='An unexpected error occurred while retrieving the HL7 message',
            error_code=500
        ), 500


@require_valid_token
@require_epic_endpoint('setMessage')
def test_set_message(token: Dict[str, Any]):
    """
    Test the Epic SetEncoderMessage endpoint with validation.
    
    Sends HL7 messages to Epic's bidirectional coding interface.
    
    Args:
        token: OAuth2 token from decorator
        
    Returns:
        Rendered form (GET) or result page (POST)
    """
    set_message_url = g.set_message_url
    epic_user_id = session.get('epic_user_id')
    
    if request.method == 'POST':
        try:
            # Get HL7 message from form
            hl7_message = request.form.get('hl7_message', '').strip()
            
            if not hl7_message:
                if request.is_json:
                    return jsonify({'error': 'HL7 message is required'}), 400
                
                return render_template(
                    'hl7/send_message.html',
                    error_message="HL7 message is required",
                    hl7_message=hl7_message
                )
            
            # Validate HL7 message structure
            validation_issues = validate_hl7_message(hl7_message)
            validation_errors = [issue for issue in validation_issues if issue['level'] == 'error']
            
            if validation_errors:
                logger.warning(f"HL7 validation failed: {validation_errors}")
                
                if request.is_json:
                    return jsonify({
                        'error': 'HL7 validation failed',
                        'validation_errors': validation_errors
                    }), 400
                
                return render_template(
                    'hl7/send_message.html',
                    validation_errors=validation_errors,
                    hl7_message=hl7_message
                )
            
            # Parse message for audit logging
            try:
                parsed_data = parse_hl7_message(hl7_message)
                patient_id = parsed_data.get('patient', {}).get('patient_id')
            except:
                patient_id = 'unknown'
            
            # Set up headers for Epic request
            headers = {
                'Authorization': f"Bearer {token['access_token']}",
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
            
            # Prepare payload
            payload = {'Message': hl7_message}
            
            # Log the attempt
            log_epic_event(
                'hl7_set_message_attempt',
                {
                    'epic_user_id': epic_user_id,
                    'patient_id': patient_id,
                    'message_length': len(hl7_message)
                }
            )
            
            # Send to Epic
            response = requests.post(
                set_message_url, 
                headers=headers, 
                json=payload, 
                timeout=30
            )
            response.raise_for_status()
            
            # Parse Epic response
            response_data = response.json()
            
            # Create audit log
            create_audit_log(
                action='hl7_message_sent',
                resource='hl7_message',
                user_id=epic_user_id,
                details={
                    'patient_id': patient_id,
                    'message_length': len(hl7_message),
                    'epic_response': response_data,
                    'success': response.ok
                }
            )
            
            logger.info("HL7 message sent to Epic successfully")
            
            if request.is_json:
                return jsonify({
                    'success': True,
                    'epic_response': response_data
                })
            
            return render_template(
                'hl7/send_result.html',
                success=True,
                epic_response=response_data,
                hl7_message=hl7_message
            )
            
        except requests.RequestException as e:
            logger.error(f"Failed to send HL7 message to Epic: {e}")
            
            if request.is_json:
                return jsonify({'error': f'Failed to send message: {str(e)}'}), 500
            
            return render_template(
                'hl7/send_result.html',
                success=False,
                error_message=f'Failed to send message to Epic: {str(e)}',
                hl7_message=hl7_message
            )
        
        except Exception as e:
            logger.error(f"Unexpected error sending HL7 message: {e}")
            
            if request.is_json:
                return jsonify({'error': 'Internal server error'}), 500
            
            return render_template(
                'hl7/send_result.html',
                success=False,
                error_message='An unexpected error occurred while sending the message',
                hl7_message=hl7_message
            )
    
    # GET request - show form
    sample_message = """MSH|^~\\&|ENCODER|VENDOR|EPIC|HOSPITAL|20241205143022||ADT^A08^ADT_A08|12345|P|2.5.1
PID|||123456789^^^MR^EPIC||DOE^JOHN^M||19801215|M||2076-8^NATIVE HAWAIIAN OR OTHER PACIFIC ISLANDER^HL70005
PV1||I|ICU^101^A|E|||1234^SMITH^JANE^M|||SUR||||A|||5678^JONES^ROBERT^L|||987654321
DG1|1||I21.9^Acute myocardial infarction, unspecified^ICD10||20241201|F||||||||||||||||||||Y|N
PR1|1||0JT70ZZ^Resection of Right Knee Joint, Open Approach^ICD10PCS|||20241202||||1234^SMITH^JANE^M"""
    
    return render_template(
        'hl7/send_message.html',
        sample_message=sample_message
    )


def test_parser():
    """
    Standalone HL7 parser testing page.
    
    Allows testing HL7 parsing without Epic connectivity.
    
    Returns:
        Rendered parser test page
    """
    if request.method == 'POST':
        hl7_message = request.form.get('hl7_message', '')
        
        if hl7_message:
            try:
                # Parse the message
                parsed_data = parse_hl7_message(hl7_message)
                
                # Get PSI data
                parser = EpicHL7Parser()
                psi_data = parser.get_psi_ready_dataframes(parsed_data)
                
                # Split into segments
                segments = hl7_message.split('\n')
                
                # Log parser usage (no Epic user context)
                log_security_event(
                    'hl7_parser_used',
                    {
                        'message_length': len(hl7_message),
                        'diagnoses_count': len(parsed_data.get('diagnoses', [])),
                        'procedures_count': len(parsed_data.get('procedures', []))
                    }
                )
                
                logger.info("HL7 message parsed successfully in standalone mode")
                
                if request.is_json:
                    return jsonify({
                        'success': True,
                        'parsed_data': parsed_data,
                        'psi_data': psi_data
                    })
                
                return render_template(
                    'hl7/parser_test.html',
                    message=hl7_message,
                    segments=segments,
                    parsed_data=parsed_data,
                    psi_data=psi_data,
                    tested=True
                )
                
            except HL7ParseError as e:
                logger.warning(f"HL7 parsing failed in standalone mode: {e}")
                
                if request.is_json:
                    return jsonify({
                        'success': False,
                        'error': str(e)
                    }), 400
                
                return render_template(
                    'hl7/parser_test.html',
                    message=hl7_message,
                    parsing_error=str(e),
                    tested=True
                )
    
    # GET request or no message - show form
    sample_message = """MSH|^~\\&|EPIC|HOSPITAL|ENCODER|VENDOR|20241205143022||ADT^A08^ADT_A08|12345|P|2.5.1
PID|||123456789^^^MR^EPIC~987654321^^^SSN||DOE^JOHN^MICHAEL||19801215|M||2076-8^NATIVE HAWAIIAN OR OTHER PACIFIC ISLANDER^HL70005|123 MAIN ST^^CHICAGO^IL^60601^USA^^^COOK||||M||12345678|123-45-6789
PV1||I|ICU^101^A|E|||1234^SMITH^JANE^M|||SUR||||A|||5678^JONES^ROBERT^L|||987654321|||||||||||||||||||||20241201120000|20241205143000
DG1|1||I21.9^Acute myocardial infarction, unspecified^ICD10||20241201|F||||||||||||||||||||Y|N
DG1|2||E11.9^Type 2 diabetes mellitus without complications^ICD10||20241201|F||||||||||||||||||||Y|N
DG1|3||N18.6^End stage renal disease^ICD10||20241201|F||||||||||||||||||||N|Y
PR1|1||0JT70ZZ^Resection of Right Knee Joint, Open Approach^ICD10PCS|||20241202||||1234^SMITH^JANE^M
PR1|2||02100Z9^Bypass Coronary Artery, One Artery from Left Internal Mammary, Open Approach^ICD10PCS|||20241203||||1234^SMITH^JANE^M
IN1|1|BCBS001|BLUE CROSS BLUE SHIELD|||||||||||20240101|20241231||||12345678||43||M"""
    
    return render_template(
        'hl7/parser_test.html',
        sample_message=sample_message,
        tested=False
    )


@require_valid_token
def message_menu(token: Dict[str, Any]):
    """
    HL7 message menu showing available HL7 operations.
    
    Args:
        token: OAuth2 token from decorator
        
    Returns:
        Rendered HL7 menu template
    """
    epic_user_id = session.get('epic_user_id')
    
    # Check available Epic endpoints
    has_get_message = bool(session.get('get_message_url'))
    has_set_message = bool(session.get('set_message_url'))
    
    # Get endpoint URLs for display
    endpoints = {
        'get_message': session.get('get_message_url'),
        'set_message': session.get('set_message_url')
    }
    
    # Log menu access
    log_epic_event(
        'hl7_menu_accessed',
        {
            'epic_user_id': epic_user_id,
            'has_get_message': has_get_message,
            'has_set_message': has_set_message
        }
    )
    
    return render_template(
        'hl7/menu.html',
        has_get_message=has_get_message,
        has_set_message=has_set_message,
        endpoints=endpoints,
        epic_user_id=epic_user_id
    )


def api_parse_hl7():
    """
    API endpoint for parsing HL7 messages (returns JSON).
    
    Accepts HL7 message in request body and returns parsed data.
    
    Returns:
        JSON response with parsed HL7 data
    """
    try:
        data = request.get_json()
        if not data or 'message' not in data:
            return jsonify({'error': 'No HL7 message provided'}), 400
        
        hl7_message = data['message']
        
        # Parse the message
        parsed_data = parse_hl7_message(hl7_message)
        
        # Get PSI data
        parser = EpicHL7Parser()
        psi_data = parser.get_psi_ready_dataframes(parsed_data)
        
        # Log API usage
        log_security_event(
            'hl7_api_parse_request',
            {
                'message_length': len(hl7_message),
                'remote_addr': request.remote_addr,
                'user_agent': request.headers.get('User-Agent')
            }
        )
        
        return jsonify({
            'success': True,
            'parsed_data': parsed_data,
            'psi_data': psi_data,
            'message': 'HL7 message parsed successfully'
        })
        
    except HL7ParseError as e:
        logger.warning(f"API HL7 parsing failed: {e}")
        return jsonify({
            'success': False,
            'error': str(e),
            'message': 'Failed to parse HL7 message'
        }), 400
        
    except Exception as e:
        logger.error(f"API HL7 parsing error: {e}")
        return jsonify({
            'success': False,
            'error': 'Internal server error',
            'message': 'Failed to parse HL7 message'
        }), 500