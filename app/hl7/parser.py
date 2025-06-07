"""
Epic HL7 ADT^A08 Parser for Clinical Quality Risk Analytics.

This module provides comprehensive parsing capabilities for Epic bidirectional 
coding interface messages, optimized for PSI (Patient Safety Indicator) 
algorithm evaluation and clinical analytics.

Features:
- Robust HL7 message parsing with error handling
- PSI-specific data extraction and validation
- Structured data output for analytics pipelines
- Comprehensive logging and monitoring
- Type hints and validation
"""

import re
from datetime import datetime
from typing import Dict, List, Optional, Any, Union, Tuple
import pandas as pd

from app.core.exceptions import HL7ParseError, HL7ValidationError
from app.core.logging import get_logger, log_performance

logger = get_logger(__name__)


class HL7FieldExtractor:
    """Utility class for extracting and parsing HL7 field components."""
    
    def __init__(self, field_separator: str = '|', component_separator: str = '^'):
        self.field_separator = field_separator
        self.component_separator = component_separator
    
    def extract_field(self, segment: str, field_num: int) -> str:
        """Extract specific field from HL7 segment."""
        try:
            fields = segment.split(self.field_separator)
            if field_num < len(fields):
                return fields[field_num].strip()
            return ""
        except Exception as e:
            logger.warning(f"Failed to extract field {field_num} from segment: {e}")
            return ""
    
    def split_components(self, field: str) -> List[str]:
        """Split field into components using ^ separator."""
        if not field:
            return []
        return [comp.strip() for comp in field.split(self.component_separator)]
    
    def extract_component(self, field: str, component_num: int) -> str:
        """Extract specific component from field."""
        components = self.split_components(field)
        if component_num < len(components):
            return components[component_num]
        return ""


class HL7DateTimeParser:
    """Utility class for parsing HL7 date/time formats."""
    
    @staticmethod
    def parse_hl7_datetime(hl7_datetime: str) -> Optional[datetime]:
        """
        Parse HL7 datetime string to Python datetime object.
        
        Supports formats: YYYYMMDD, YYYYMMDDHHMM, YYYYMMDDHHMMSS
        """
        if not hl7_datetime:
            return None
        
        # Remove any non-digit characters
        clean_datetime = re.sub(r'\D', '', hl7_datetime)
        
        try:
            if len(clean_datetime) >= 8:
                year = int(clean_datetime[:4])
                month = int(clean_datetime[4:6])
                day = int(clean_datetime[6:8])
                
                hour = int(clean_datetime[8:10]) if len(clean_datetime) >= 10 else 0
                minute = int(clean_datetime[10:12]) if len(clean_datetime) >= 12 else 0
                second = int(clean_datetime[12:14]) if len(clean_datetime) >= 14 else 0
                
                return datetime(year, month, day, hour, minute, second)
        except (ValueError, IndexError) as e:
            logger.warning(f"Failed to parse HL7 datetime '{hl7_datetime}': {e}")
        
        return None
    
    @staticmethod
    def format_hl7_date(dt: datetime) -> str:
        """Format datetime as HL7 date string (YYYYMMDD)."""
        return dt.strftime("%Y%m%d")
    
    @staticmethod
    def format_hl7_datetime(dt: datetime) -> str:
        """Format datetime as HL7 datetime string (YYYYMMDDHHMMSS)."""
        return dt.strftime("%Y%m%d%H%M%S")


class HL7SegmentParser:
    """Base class for parsing specific HL7 segment types."""
    
    def __init__(self, extractor: HL7FieldExtractor):
        self.extractor = extractor
    
    def parse(self, segment: str) -> Dict[str, Any]:
        """Parse segment into structured data. Override in subclasses."""
        raise NotImplementedError


class MSHParser(HL7SegmentParser):
    """Parser for MSH (Message Header) segments."""
    
    def parse(self, segment: str) -> Dict[str, Any]:
        """Parse MSH segment."""
        return {
            'message_type': self.extractor.extract_field(segment, 9),
            'message_control_id': self.extractor.extract_field(segment, 10),
            'timestamp': self.extractor.extract_field(segment, 7),
            'sending_application': self.extractor.extract_field(segment, 3),
            'receiving_application': self.extractor.extract_field(segment, 5),
            'version_id': self.extractor.extract_field(segment, 12)
        }


class PIDParser(HL7SegmentParser):
    """Parser for PID (Patient Identification) segments."""
    
    def parse(self, segment: str) -> Dict[str, Any]:
        """Parse PID segment with enhanced name parsing."""
        patient_name_raw = self.extractor.extract_field(segment, 5)
        name_components = self.extractor.split_components(patient_name_raw)
        
        # Parse address
        address_raw = self.extractor.extract_field(segment, 11)
        address_components = self.extractor.split_components(address_raw)
        
        return {
            'patient_id': self.extractor.extract_field(segment, 3),
            'account_number': self.extractor.extract_field(segment, 18),
            'last_name': name_components[0] if len(name_components) > 0 else '',
            'first_name': name_components[1] if len(name_components) > 1 else '',
            'middle_name': name_components[2] if len(name_components) > 2 else '',
            'name_suffix': name_components[4] if len(name_components) > 4 else '',
            'date_of_birth': self.extractor.extract_field(segment, 7),
            'sex': self.extractor.extract_field(segment, 8),
            'race': self.extractor.extract_field(segment, 10),
            'address_line_1': address_components[0] if len(address_components) > 0 else '',
            'address_line_2': address_components[1] if len(address_components) > 1 else '',
            'city': address_components[2] if len(address_components) > 2 else '',
            'state': address_components[3] if len(address_components) > 3 else '',
            'zip_code': address_components[4] if len(address_components) > 4 else '',
            'marital_status': self.extractor.extract_field(segment, 16),
            'ssn': self.extractor.extract_field(segment, 19)
        }


class PV1Parser(HL7SegmentParser):
    """Parser for PV1 (Patient Visit) segments."""
    
    def parse(self, segment: str) -> Dict[str, Any]:
        """Parse PV1 segment with enhanced provider parsing."""
        attending_raw = self.extractor.extract_field(segment, 7)
        attending_components = self.extractor.split_components(attending_raw)
        
        admitting_raw = self.extractor.extract_field(segment, 17)
        admitting_components = self.extractor.split_components(admitting_raw)
        
        return {
            'patient_class': self.extractor.extract_field(segment, 2),
            'patient_location': self.extractor.extract_field(segment, 3),
            'admission_type': self.extractor.extract_field(segment, 4),
            'preadmit_number': self.extractor.extract_field(segment, 5),
            'prior_patient_location': self.extractor.extract_field(segment, 6),
            'attending_physician_id': attending_components[0] if len(attending_components) > 0 else '',
            'attending_physician_last_name': attending_components[1] if len(attending_components) > 1 else '',
            'attending_physician_first_name': attending_components[2] if len(attending_components) > 2 else '',
            'attending_physician_name': f"{attending_components[1]} {attending_components[2]}".strip() 
                                     if len(attending_components) > 2 else '',
            'admitting_physician_id': admitting_components[0] if len(admitting_components) > 0 else '',
            'admitting_physician_name': f"{admitting_components[1]} {admitting_components[2]}".strip()
                                      if len(admitting_components) > 2 else '',
            'visit_number': self.extractor.extract_field(segment, 19),
            'financial_class': self.extractor.extract_field(segment, 20),
            'discharge_disposition': self.extractor.extract_field(segment, 36),
            'admit_timestamp': self.extractor.extract_field(segment, 44),
            'discharge_timestamp': self.extractor.extract_field(segment, 45),
            'visit_indicator': self.extractor.extract_field(segment, 51)
        }


class DG1Parser(HL7SegmentParser):
    """Parser for DG1 (Diagnosis) segments with PSI optimization."""
    
    def parse(self, segment: str) -> Optional[Dict[str, Any]]:
        """Parse DG1 segment - optimized for PSI risk analytics."""
        diagnosis_code_raw = self.extractor.extract_field(segment, 3)
        if not diagnosis_code_raw:
            return None
            
        diagnosis_components = self.extractor.split_components(diagnosis_code_raw)
        
        # Parse POA indicator (field 26)
        poa_indicator = self.extractor.extract_field(segment, 26)
        
        # Parse HAC indicator (field 27) 
        hac_indicator = self.extractor.extract_field(segment, 27)
        
        # Parse diagnosis type (field 6)
        diagnosis_type = self.extractor.extract_field(segment, 6)
        
        # Parse clinician information
        clinician_raw = self.extractor.extract_field(segment, 16)
        clinician_components = self.extractor.split_components(clinician_raw)
        
        return {
            'set_id': self.extractor.extract_field(segment, 1),
            'diagnosis_coding_method': self.extractor.extract_field(segment, 2),
            'diagnosis_code': diagnosis_components[0] if len(diagnosis_components) > 0 else '',
            'diagnosis_description': diagnosis_components[1] if len(diagnosis_components) > 1 else '',
            'code_set': diagnosis_components[2] if len(diagnosis_components) > 2 else '',
            'diagnosis_type': diagnosis_type,  # A=Admit, F=Final, VI=Visit
            'major_diagnostic_category': self.extractor.extract_field(segment, 4),
            'effective_date': self.extractor.extract_field(segment, 5),
            'diagnosis_priority': self.extractor.extract_field(segment, 15),
            'diagnosing_clinician_id': clinician_components[0] if len(clinician_components) > 0 else '',
            'diagnosing_clinician_name': f"{clinician_components[1]} {clinician_components[2]}".strip()
                                       if len(clinician_components) > 2 else '',
            'poa_indicator': poa_indicator,  # Critical for PSI algorithms
            'hac_indicator': hac_indicator,   # Y/N for Hospital Acquired Conditions
            'is_final_diagnosis': diagnosis_type == 'F',
            'is_admit_diagnosis': diagnosis_type == 'A',
            'is_present_on_admission': poa_indicator.upper() == 'Y',
            'is_hospital_acquired': hac_indicator.upper() == 'Y'
        }


class PR1Parser(HL7SegmentParser):
    """Parser for PR1 (Procedure) segments with enhanced procedure data."""
    
    def parse(self, segment: str) -> Optional[Dict[str, Any]]:
        """Parse PR1 segment - focused on ICD-10-PCS codes and dates."""
        procedure_code_raw = self.extractor.extract_field(segment, 3)
        if not procedure_code_raw:
            return None
            
        procedure_components = self.extractor.split_components(procedure_code_raw)
        procedure_date_raw = self.extractor.extract_field(segment, 5)
        
        # Extract surgeon info
        surgeon_raw = self.extractor.extract_field(segment, 11)
        surgeon_components = self.extractor.split_components(surgeon_raw)
        
        # Extract anesthesiologist info
        anesthesiologist_raw = self.extractor.extract_field(segment, 12)
        anesthesiologist_components = self.extractor.split_components(anesthesiologist_raw)
        
        return {
            'set_id': self.extractor.extract_field(segment, 1),
            'procedure_coding_method': self.extractor.extract_field(segment, 2),
            'procedure_code': procedure_components[0] if len(procedure_components) > 0 else '',
            'procedure_description': procedure_components[1] if len(procedure_components) > 1 else '',
            'procedure_type': procedure_components[2] if len(procedure_components) > 2 else '',
            'procedure_functional_type': self.extractor.extract_field(segment, 6),
            'procedure_priority': self.extractor.extract_field(segment, 14),
            'procedure_date': procedure_date_raw[:8] if procedure_date_raw else '',  # YYYYMMDD format
            'procedure_datetime': procedure_date_raw,
            'procedure_minutes': self.extractor.extract_field(segment, 10),
            'surgeon_id': surgeon_components[0] if len(surgeon_components) > 0 else '',
            'surgeon_last_name': surgeon_components[1] if len(surgeon_components) > 1 else '',
            'surgeon_first_name': surgeon_components[2] if len(surgeon_components) > 2 else '',
            'surgeon_name': f"{surgeon_components[1]} {surgeon_components[2]}".strip() 
                          if len(surgeon_components) > 2 else '',
            'anesthesiologist_id': anesthesiologist_components[0] if len(anesthesiologist_components) > 0 else '',
            'anesthesiologist_name': f"{anesthesiologist_components[1]} {anesthesiologist_components[2]}".strip()
                                   if len(anesthesiologist_components) > 2 else '',
            'is_icd10_pcs': procedure_components[2] == 'I10' if len(procedure_components) > 2 else False,
            'modifiers': self.extractor.extract_field(segment, 16),
            'consent_code': self.extractor.extract_field(segment, 19)
        }


class IN1Parser(HL7SegmentParser):
    """Parser for IN1 (Insurance) segments."""
    
    def parse(self, segment: str) -> Optional[Dict[str, Any]]:
        """Parse IN1 segment - insurance information for context."""
        plan_id = self.extractor.extract_field(segment, 2)
        if not plan_id:
            return None
        
        # Parse insured's name
        insured_name_raw = self.extractor.extract_field(segment, 16)
        name_components = self.extractor.split_components(insured_name_raw)
        
        return {
            'set_id': self.extractor.extract_field(segment, 1),
            'insurance_plan_id': plan_id,
            'insurance_company_id': self.extractor.extract_field(segment, 3),
            'insurance_company_name': self.extractor.extract_field(segment, 4),
            'group_number': self.extractor.extract_field(segment, 8),
            'group_name': self.extractor.extract_field(segment, 9),
            'plan_effective_date': self.extractor.extract_field(segment, 12),
            'plan_expiration_date': self.extractor.extract_field(segment, 13),
            'authorization_info': self.extractor.extract_field(segment, 14),
            'plan_type': self.extractor.extract_field(segment, 15),
            'insured_last_name': name_components[0] if len(name_components) > 0 else '',
            'insured_first_name': name_components[1] if len(name_components) > 1 else '',
            'relationship_to_patient': self.extractor.extract_field(segment, 17),
            'policy_number': self.extractor.extract_field(segment, 36),
            'coordination_of_benefits': self.extractor.extract_field(segment, 22)
        }


class EpicHL7Parser:
    """
    Enhanced Epic HL7 ADT^A08 Parser for clinical quality risk analytics.
    
    Features:
    - Comprehensive segment parsing with validation
    - PSI-specific data extraction
    - Enhanced error handling and logging
    - Performance monitoring
    - Type hints and structured output
    """
    
    def __init__(self):
        """Initialize parser with field separators and segment parsers."""
        self.field_separator = '|'
        self.component_separator = '^'
        self.repetition_separator = '~'
        self.escape_character = '\\'
        self.subcomponent_separator = '&'
        
        # Initialize field extractor
        self.extractor = HL7FieldExtractor(self.field_separator, self.component_separator)
        
        # Initialize segment parsers
        self.parsers = {
            'MSH': MSHParser(self.extractor),
            'PID': PIDParser(self.extractor),
            'PV1': PV1Parser(self.extractor),
            'DG1': DG1Parser(self.extractor),
            'PR1': PR1Parser(self.extractor),
            'IN1': IN1Parser(self.extractor)
        }
    
    def parse_message(self, hl7_message: str) -> Dict[str, Any]:
        """
        Parse complete HL7 ADT^A08 message into structured dictionary.
        
        Args:
            hl7_message: Raw HL7 message string
            
        Returns:
            Dict containing parsed patient, visit, diagnosis, and procedure data
            
        Raises:
            HL7ParseError: If message parsing fails
        """
        if not hl7_message or not hl7_message.strip():
            raise HL7ParseError("HL7 message is empty or None")
        
        with log_performance("hl7_message_parsing", logger):
            try:
                # Split message into segments
                segments = self._split_message_segments(hl7_message)
                
                if not segments:
                    raise HL7ParseError("No valid segments found in HL7 message")
                
                # Initialize parsed data structure
                parsed_data = {
                    'message_info': {},
                    'patient': {},
                    'visit': {},
                    'diagnoses': [],
                    'procedures': [],
                    'insurance': [],
                    'parsing_errors': [],
                    'parsing_warnings': []
                }
                
                # Parse each segment
                for segment_line in segments:
                    try:
                        self._parse_segment(segment_line, parsed_data)
                    except Exception as e:
                        error_msg = f"Failed to parse segment: {str(e)}"
                        logger.warning(error_msg, extra={'segment': segment_line[:50]})
                        parsed_data['parsing_errors'].append({
                            'segment': segment_line[:50] + '...' if len(segment_line) > 50 else segment_line,
                            'error': str(e)
                        })
                
                # Add summary counts for validation
                parsed_data['summary'] = self._generate_summary(parsed_data)
                
                # Validate parsed data
                self._validate_parsed_data(parsed_data)
                
                logger.info(
                    "HL7 message parsed successfully",
                    extra={
                        'diagnoses_count': len(parsed_data['diagnoses']),
                        'procedures_count': len(parsed_data['procedures']),
                        'errors_count': len(parsed_data['parsing_errors'])
                    }
                )
                
                return parsed_data
                
            except Exception as e:
                error_msg = f"Failed to parse HL7 message: {str(e)}"
                logger.error(error_msg)
                raise HL7ParseError(error_msg, original_error=e)
    
    def _split_message_segments(self, hl7_message: str) -> List[str]:
        """Split HL7 message into individual segments."""
        # Handle different line ending types
        segments = []
        
        # Split by various line endings
        for line_ending in ['\r\n', '\n', '\r']:
            if line_ending in hl7_message:
                segments = [seg.strip() for seg in hl7_message.split(line_ending) if seg.strip()]
                break
        
        if not segments:
            # If no line endings found, treat as single segment
            segments = [hl7_message.strip()] if hl7_message.strip() else []
        
        return segments
    
    def _parse_segment(self, segment_line: str, parsed_data: Dict[str, Any]) -> None:
        """Parse individual segment based on segment type."""
        if len(segment_line) < 3:
            return
        
        segment_type = segment_line[:3]
        
        if segment_type in self.parsers:
            try:
                parser = self.parsers[segment_type]
                result = parser.parse(segment_line)
                
                if result is None:
                    return
                
                # Store parsed data based on segment type
                if segment_type == 'MSH':
                    parsed_data['message_info'] = result
                elif segment_type == 'PID':
                    parsed_data['patient'] = result
                elif segment_type == 'PV1':
                    parsed_data['visit'] = result
                elif segment_type == 'DG1':
                    parsed_data['diagnoses'].append(result)
                elif segment_type == 'PR1':
                    parsed_data['procedures'].append(result)
                elif segment_type == 'IN1':
                    parsed_data['insurance'].append(result)
                    
            except Exception as e:
                logger.warning(f"Failed to parse {segment_type} segment: {e}")
                parsed_data['parsing_errors'].append({
                    'segment_type': segment_type,
                    'segment': segment_line[:50] + '...' if len(segment_line) > 50 else segment_line,
                    'error': str(e)
                })
        else:
            # Log unknown segment types for debugging
            logger.debug(f"Unknown segment type: {segment_type}")
    
    def _generate_summary(self, parsed_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate summary statistics for parsed data."""
        return {
            'diagnosis_count': len(parsed_data['diagnoses']),
            'procedure_count': len(parsed_data['procedures']),
            'insurance_count': len(parsed_data['insurance']),
            'parsing_error_count': len(parsed_data['parsing_errors']),
            'has_patient_data': bool(parsed_data['patient']),
            'has_visit_data': bool(parsed_data['visit']),
            'message_type': parsed_data.get('message_info', {}).get('message_type', 'Unknown')
        }
    
    def _validate_parsed_data(self, parsed_data: Dict[str, Any]) -> None:
        """Validate parsed data for completeness and consistency."""
        warnings = []
        
        # Check for required data
        if not parsed_data['patient']:
            warnings.append("No patient information found in message")
        
        if not parsed_data['visit']:
            warnings.append("No visit information found in message")
        
        # Check for PSI-critical fields
        diagnoses_with_poa = sum(1 for dx in parsed_data['diagnoses'] 
                               if dx.get('poa_indicator'))
        
        if parsed_data['diagnoses'] and diagnoses_with_poa == 0:
            warnings.append("No diagnoses have POA (Present on Admission) indicators")
        
        # Add warnings to parsed data
        parsed_data['parsing_warnings'].extend(warnings)
        
        if warnings:
            logger.warning(f"Validation warnings: {warnings}")
    
    def get_psi_ready_dataframes(self, parsed_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convert parsed data to pandas-ready format for PSI algorithm application.
        
        Args:
            parsed_data: Parsed HL7 message data
            
        Returns:
            Dictionary with patient info and lists ready for DataFrame conversion
        """
        with log_performance("psi_data_preparation", logger):
            # Base patient/visit info for joining
            base_info = {
                'patient_id': parsed_data['patient'].get('patient_id', ''),
                'account_number': parsed_data['patient'].get('account_number', ''),
                'visit_number': parsed_data['visit'].get('visit_number', ''),
                'patient_class': parsed_data['visit'].get('patient_class', ''),
                'admission_type': parsed_data['visit'].get('admission_type', ''),
                'admit_date': parsed_data['visit'].get('admit_timestamp', '')[:8],  # YYYYMMDD
                'discharge_date': parsed_data['visit'].get('discharge_timestamp', '')[:8],
                'patient_age': self._calculate_age(parsed_data['patient'].get('date_of_birth', '')),
                'patient_sex': parsed_data['patient'].get('sex', ''),
                'discharge_disposition': parsed_data['visit'].get('discharge_disposition', '')
            }
            
            # Prepare diagnoses for PSI algorithm
            diagnosis_records = []
            for i, dx in enumerate(parsed_data['diagnoses']):
                record = base_info.copy()
                record.update({
                    'diagnosis_sequence': i + 1,
                    'diagnosis_code': dx.get('diagnosis_code', ''),
                    'diagnosis_description': dx.get('diagnosis_description', ''),
                    'diagnosis_type': dx.get('diagnosis_type', ''),
                    'poa_indicator': dx.get('poa_indicator', ''),
                    'hac_indicator': dx.get('hac_indicator', ''),
                    'is_present_on_admission': dx.get('is_present_on_admission', False),
                    'is_final_diagnosis': dx.get('is_final_diagnosis', False),
                    'is_primary_diagnosis': i == 0 and dx.get('is_final_diagnosis', False),
                    'major_diagnostic_category': dx.get('major_diagnostic_category', ''),
                    'diagnosis_priority': dx.get('diagnosis_priority', '')
                })
                diagnosis_records.append(record)
            
            # Prepare procedures for PSI algorithm
            procedure_records = []
            for i, proc in enumerate(parsed_data['procedures']):
                record = base_info.copy()
                record.update({
                    'procedure_sequence': i + 1,
                    'procedure_code': proc.get('procedure_code', ''),
                    'procedure_description': proc.get('procedure_description', ''),
                    'procedure_date': proc.get('procedure_date', ''),
                    'procedure_datetime': proc.get('procedure_datetime', ''),
                    'is_icd10_pcs': proc.get('is_icd10_pcs', False),
                    'surgeon_id': proc.get('surgeon_id', ''),
                    'procedure_priority': proc.get('procedure_priority', ''),
                    'procedure_minutes': proc.get('procedure_minutes', '')
                })
                procedure_records.append(record)
            
            # Calculate enhanced summary statistics
            enhanced_summary = {
                'total_diagnoses': len(diagnosis_records),
                'total_procedures': len(procedure_records),
                'icd10_pcs_procedures': sum(1 for p in parsed_data['procedures'] 
                                          if p.get('is_icd10_pcs', False)),
                'poa_yes_diagnoses': sum(1 for d in parsed_data['diagnoses'] 
                                       if d.get('is_present_on_admission', False)),
                'poa_no_diagnoses': sum(1 for d in parsed_data['diagnoses'] 
                                      if d.get('poa_indicator', '').upper() == 'N'),
                'hac_flagged_diagnoses': sum(1 for d in parsed_data['diagnoses'] 
                                           if d.get('hac_indicator', '').upper() == 'Y'),
                'final_diagnoses': sum(1 for d in parsed_data['diagnoses'] 
                                     if d.get('is_final_diagnosis', False)),
                'admit_diagnoses': sum(1 for d in parsed_data['diagnoses'] 
                                     if d.get('is_admit_diagnosis', False)),
                'patient_age': base_info['patient_age'],
                'length_of_stay_days': self._calculate_los(
                    base_info['admit_date'], 
                    base_info['discharge_date']
                )
            }
            
            return {
                'patient_info': base_info,
                'diagnoses_df_ready': diagnosis_records,
                'procedures_df_ready': procedure_records,
                'summary': enhanced_summary
            }
    
    def _calculate_age(self, date_of_birth: str) -> Optional[int]:
        """Calculate age from HL7 date of birth string."""
        if not date_of_birth:
            return None
        
        try:
            dob = HL7DateTimeParser.parse_hl7_datetime(date_of_birth)
            if dob:
                today = datetime.now()
                age = today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))
                return age
        except Exception as e:
            logger.warning(f"Failed to calculate age from DOB '{date_of_birth}': {e}")
        
        return None
    
    def _calculate_los(self, admit_date: str, discharge_date: str) -> Optional[int]:
        """Calculate length of stay in days."""
        if not admit_date or not discharge_date:
            return None
        
        try:
            admit_dt = HL7DateTimeParser.parse_hl7_datetime(admit_date)
            discharge_dt = HL7DateTimeParser.parse_hl7_datetime(discharge_date)
            
            if admit_dt and discharge_dt:
                los = (discharge_dt - admit_dt).days
                return max(0, los)  # Ensure non-negative LOS
        except Exception as e:
            logger.warning(f"Failed to calculate LOS: {e}")
        
        return None
    
    def to_dataframes(self, parsed_data: Dict[str, Any]) -> Dict[str, pd.DataFrame]:
        """
        Convert parsed data directly to pandas DataFrames.
        
        Args:
            parsed_data: Parsed HL7 message data
            
        Returns:
            Dictionary containing DataFrames for different data types
        """
        psi_data = self.get_psi_ready_dataframes(parsed_data)
        
        dataframes = {}
        
        # Create diagnoses DataFrame
        if psi_data['diagnoses_df_ready']:
            dataframes['diagnoses'] = pd.DataFrame(psi_data['diagnoses_df_ready'])
        
        # Create procedures DataFrame
        if psi_data['procedures_df_ready']:
            dataframes['procedures'] = pd.DataFrame(psi_data['procedures_df_ready'])
        
        # Create patient/visit DataFrame
        if psi_data['patient_info']:
            dataframes['patient_visit'] = pd.DataFrame([psi_data['patient_info']])
        
        logger.info(f"Created {len(dataframes)} DataFrames from parsed data")
        return dataframes
    
    def validate_message_structure(self, hl7_message: str) -> List[Dict[str, Any]]:
        """
        Validate HL7 message structure without full parsing.
        
        Args:
            hl7_message: Raw HL7 message string
            
        Returns:
            List of validation issues found
        """
        issues = []
        
        try:
            segments = self._split_message_segments(hl7_message)
            
            if not segments:
                issues.append({
                    'level': 'error',
                    'message': 'No segments found in HL7 message',
                    'segment': None
                })
                return issues
            
            # Check for required MSH segment
            has_msh = any(seg.startswith('MSH') for seg in segments)
            if not has_msh:
                issues.append({
                    'level': 'error',
                    'message': 'Missing required MSH (Message Header) segment',
                    'segment': None
                })
            
            # Check for patient identification
            has_pid = any(seg.startswith('PID') for seg in segments)
            if not has_pid:
                issues.append({
                    'level': 'warning',
                    'message': 'Missing PID (Patient Identification) segment',
                    'segment': None
                })
            
            # Validate individual segments
            for i, segment in enumerate(segments):
                if len(segment) < 3:
                    issues.append({
                        'level': 'warning',
                        'message': f'Segment {i+1} is too short',
                        'segment': segment
                    })
                    continue
                
                # Check field separator consistency
                if not segment[3:4] == self.field_separator:
                    issues.append({
                        'level': 'warning',
                        'message': f'Segment {i+1} may have incorrect field separator',
                        'segment': segment[:20] + '...'
                    })
        
        except Exception as e:
            issues.append({
                'level': 'error',
                'message': f'Validation failed: {str(e)}',
                'segment': None
            })
        
        return issues
    
    def extract_patient_identifiers(self, hl7_message: str) -> Dict[str, str]:
        """
        Quickly extract patient identifiers without full parsing.
        
        Args:
            hl7_message: Raw HL7 message string
            
        Returns:
            Dictionary of patient identifiers
        """
        identifiers = {}
        
        try:
            segments = self._split_message_segments(hl7_message)
            
            for segment in segments:
                if segment.startswith('PID'):
                    # Extract patient ID (field 3)
                    patient_id = self.extractor.extract_field(segment, 3)
                    if patient_id:
                        identifiers['patient_id'] = patient_id
                    
                    # Extract account number (field 18)
                    account_number = self.extractor.extract_field(segment, 18)
                    if account_number:
                        identifiers['account_number'] = account_number
                    
                    # Extract SSN (field 19)
                    ssn = self.extractor.extract_field(segment, 19)
                    if ssn:
                        identifiers['ssn'] = ssn
                    
                    break
                
                elif segment.startswith('PV1'):
                    # Extract visit number (field 19)
                    visit_number = self.extractor.extract_field(segment, 19)
                    if visit_number:
                        identifiers['visit_number'] = visit_number
        
        except Exception as e:
            logger.warning(f"Failed to extract patient identifiers: {e}")
        
        return identifiers
    
    def get_segment_counts(self, hl7_message: str) -> Dict[str, int]:
        """
        Get count of each segment type in the message.
        
        Args:
            hl7_message: Raw HL7 message string
            
        Returns:
            Dictionary mapping segment types to counts
        """
        counts = {}
        
        try:
            segments = self._split_message_segments(hl7_message)
            
            for segment in segments:
                if len(segment) >= 3:
                    segment_type = segment[:3]
                    counts[segment_type] = counts.get(segment_type, 0) + 1
        
        except Exception as e:
            logger.warning(f"Failed to count segments: {e}")
        
        return counts


# Utility functions for common operations
def parse_hl7_message(hl7_message: str) -> Dict[str, Any]:
    """
    Convenience function to parse an HL7 message.
    
    Args:
        hl7_message: Raw HL7 message string
        
    Returns:
        Parsed message data
    """
    parser = EpicHL7Parser()
    return parser.parse_message(hl7_message)


def validate_hl7_message(hl7_message: str) -> List[Dict[str, Any]]:
    """
    Convenience function to validate an HL7 message structure.
    
    Args:
        hl7_message: Raw HL7 message string
        
    Returns:
        List of validation issues
    """
    parser = EpicHL7Parser()
    return parser.validate_message_structure(hl7_message)


def extract_patient_info(hl7_message: str) -> Dict[str, str]:
    """
    Convenience function to extract basic patient information.
    
    Args:
        hl7_message: Raw HL7 message string
        
    Returns:
        Patient identifiers and basic info
    """
    parser = EpicHL7Parser()
    return parser.extract_patient_identifiers(hl7_message)


# Example usage and testing function
def test_parser():
    """Test function with sample HL7 message structure."""
    
    sample_hl7 = """MSH|^~\\&|EPIC|HOSPITAL|ENCODER|VENDOR|20241205143022||ADT^A08^ADT_A08|12345|P|2.5.1
EVN|A08|20241205143022|||12345^PROVIDER^TEST^^
PID|||123456789^^^MR^EPIC~987654321^^^SSN||DOE^JOHN^MICHAEL||19801215|M||2076-8^NATIVE HAWAIIAN OR OTHER PACIFIC ISLANDER^HL70005|123 MAIN ST^^CHICAGO^IL^60601^USA^^^COOK||||M||12345678|123-45-6789
PV1||I|ICU^101^A|E|||1234^SMITH^JANE^M|||SUR||||A|||5678^JONES^ROBERT^L|||987654321|||||||||||||||||||||20241201120000|20241205143000
DG1|1||I21.9^Acute myocardial infarction, unspecified^ICD10||20241201|F||||||||||||||||||||Y|N
DG1|2||E11.9^Type 2 diabetes mellitus without complications^ICD10||20241201|F||||||||||||||||||||Y|N
DG1|3||N18.6^End stage renal disease^ICD10||20241201|F||||||||||||||||||||N|Y
PR1|1||0JT70ZZ^Resection of Right Knee Joint, Open Approach^ICD10PCS|||20241202||||1234^SMITH^JANE^M
PR1|2||02100Z9^Bypass Coronary Artery, One Artery from Left Internal Mammary, Open Approach^ICD10PCS|||20241203||||1234^SMITH^JANE^M
IN1|1|BCBS001|BLUE CROSS BLUE SHIELD|||||||||||20240101|20241231||||12345678||43||M"""

    parser = EpicHL7Parser()
    
    print("=== HL7 MESSAGE VALIDATION ===")
    validation_issues = parser.validate_message_structure(sample_hl7)
    print(f"Validation issues found: {len(validation_issues)}")
    for issue in validation_issues:
        print(f"  {issue['level'].upper()}: {issue['message']}")
    
    print("\n=== SEGMENT COUNTS ===")
    segment_counts = parser.get_segment_counts(sample_hl7)
    for segment_type, count in segment_counts.items():
        print(f"  {segment_type}: {count}")
    
    print("\n=== PATIENT IDENTIFIERS ===")
    identifiers = parser.extract_patient_identifiers(sample_hl7)
    for key, value in identifiers.items():
        print(f"  {key}: {value}")
    
    print("\n=== FULL PARSING ===")
    result = parser.parse_message(sample_hl7)
    
    print(f"Patient: {result['patient']['first_name']} {result['patient']['last_name']}")
    print(f"Account: {result['patient']['account_number']}")
    print(f"Diagnoses: {len(result['diagnoses'])}")
    print(f"Procedures: {len(result['procedures'])}")
    print(f"Parsing errors: {len(result['parsing_errors'])}")
    
    print("\n=== DIAGNOSIS DETAILS ===")
    for dx in result['diagnoses']:
        print(f"  {dx['diagnosis_code']}: {dx['diagnosis_description']} (POA: {dx['poa_indicator']})")
    
    print("\n=== PROCEDURE DETAILS ===")
    for proc in result['procedures']:
        print(f"  {proc['procedure_code']}: {proc['procedure_description']} ({proc['procedure_date']})")
    
    # Test PSI-ready format
    psi_data = parser.get_psi_ready_dataframes(result)
    print(f"\n=== PSI SUMMARY ===")
    for key, value in psi_data['summary'].items():
        print(f"  {key}: {value}")
    
    # Test DataFrame creation
    print("\n=== DATAFRAMES ===")
    dataframes = parser.to_dataframes(result)
    for df_name, df in dataframes.items():
        print(f"  {df_name}: {df.shape}")
    
    return result, psi_data


if __name__ == "__main__":
    test_parser()