from typing import List, Dict, Optional, Set
from app.models.patient import Patient, Diagnosis
from app.services.reference_service import ReferenceService
from app.utils.code_utils import clean_icd_code, strip_cc_suffix

class AnalysisService:
    """Service for analyzing patient diagnoses for Heart Failure risk assessment"""
    
    def __init__(self, reference_service: ReferenceService):
        """Initialize with reference data service"""
        self.reference_service = reference_service
    
    def analyze_patient(self, patient: Patient) -> None:
        """
        Analyze a patient's diagnoses and update the patient object with Heart Failure results
        
        Args:
            patient: The patient to analyze
        """
        # Skip empty patients
        if not patient.diagnoses:
            patient.qualifies_for_hf_cohort = False
            return
        
        # Process each diagnosis
        for dx in patient.diagnoses:
            # Calculate comorbidity risk
            self._calculate_comorbidity_risk(dx)
            
            # Determine MCC/CC/HAC status
            self._determine_mcc_cc_status(dx)
        
        # Check qualification based on primary diagnosis
        primary_dx = patient.get_primary_diagnosis()
        if not primary_dx:
            patient.qualifies_for_hf_cohort = False
            return
        
        # Primary diagnosis POA must be Y or E for Heart Failure qualification
        if primary_dx.poa_status not in ['Y', 'E']:
            patient.qualifies_for_hf_cohort = False
            return
        
        # Primary diagnosis must be a qualifying Heart Failure code
        qualifies_for_hf_cohort = self._is_qualifying_diagnosis(primary_dx.icd_code)
        
        # Check for exclusion codes with POA=Y
        has_exclusion = False
        exclusion_details = []
        
        for dx in patient.diagnoses:
            if not dx.is_primary:
                # Check for exclusion codes with POA=Y (present on admission)
                if self._is_exclusion_diagnosis(dx.icd_code) and dx.poa_status in ['Y', 'E', 'W']:
                    has_exclusion = True
                    exclusion_details.append({
                        'row': dx.sequence_number,
                        'code': dx.icd_code
                    })
        
        # Update patient with analysis results
        patient.qualifies_for_hf_cohort = qualifies_for_hf_cohort and not has_exclusion
        patient.has_exclusion = has_exclusion
        patient.exclusion_details = exclusion_details
        
        # Process risk variables for summary
        self._process_risk_variables(patient)
        
        # Generate smart POA issues (only show truly problematic ones)
        patient.risk_poa_issues = self._generate_smart_poa_issues(patient)
    
    def _calculate_comorbidity_risk(self, dx: Diagnosis) -> None:
        """
        Calculate Heart Failure comorbidity risk for a diagnosis with 2025 POA logic
        
        Args:
            dx: The diagnosis to analyze
        """
        # Primary diagnosis doesn't get a risk variable
        if dx.is_primary:
            dx.comorbidity_risk_variable = ""
            dx.models = ""
            return
        
        # Skip empty codes
        if not dx.icd_code:
            dx.comorbidity_risk_variable = ""
            dx.models = ""
            return
        
        # Get risk info from reference service
        risk_info = self.reference_service.get_risk_variable(dx.icd_code)
        
        # If not in mapping, return empty strings
        if not risk_info:
            dx.comorbidity_risk_variable = ""
            dx.models = ""
            return
        
        # 2025 LOGIC: Check if POA is required for this risk variable
        poa_required = risk_info.get("poa_required", "Y")  # Default to Y if not specified
        
        if poa_required == "N":
            # POA not required - always assign the risk variable regardless of POA status
            dx.comorbidity_risk_variable = risk_info["risk_variable"]
            dx.models = risk_info["models"]
        else:
            # POA required - use original logic
            # Y, E, and W are treated as Present on Admission
            # N and U are treated as Not Present on Admission
            if dx.poa_status in ['Y', 'E', 'W']:
                dx.comorbidity_risk_variable = risk_info["risk_variable"]
                dx.models = risk_info["models"]
            elif dx.poa_status in ['N', 'U']:
                dx.comorbidity_risk_variable = f"{risk_info['risk_variable']} (Not Present on Admission)"
                dx.models = risk_info["models"]
            else:
                # Invalid or empty POA status
                dx.comorbidity_risk_variable = ""
                dx.models = ""
    
    def _determine_mcc_cc_status(self, dx: Diagnosis) -> None:
        """
        Determine MCC/CC/HAC status for a diagnosis using the new logic
        
        Args:
            dx: The diagnosis to analyze
        """
        # Primary diagnosis doesn't get MCC/CC designation
        if dx.is_primary:
            dx.mcc_cc_status = ""
            return
        
        # Skip empty codes
        if not dx.icd_code:
            dx.mcc_cc_status = ""
            return
        
        # First check if the code is in MCC or CC lists
        is_mcc = self.reference_service.is_mcc(dx.icd_code)
        is_cc = self.reference_service.is_cc(dx.icd_code)
        
        # If it's neither MCC nor CC, return empty
        if not is_mcc and not is_cc:
            dx.mcc_cc_status = ""
            return
        
        # Apply the logic based on POA status
        if dx.poa_status in ['Y', 'W']:
            # POA = Y or W: assign MCC/CC as normal
            if is_mcc:
                dx.mcc_cc_status = "MCC"
            elif is_cc:
                dx.mcc_cc_status = "CC"
        elif dx.poa_status in ['N', 'U', 'E']:
            # POA = N, U, or E: check if it's a HAC
            if self.reference_service.is_hac(dx.icd_code):
                dx.mcc_cc_status = "HAC"
            else:
                # Not a HAC, so assign MCC/CC as normal
                if is_mcc:
                    dx.mcc_cc_status = "MCC"
                elif is_cc:
                    dx.mcc_cc_status = "CC"
        else:
            # Invalid or empty POA status
            dx.mcc_cc_status = ""
    
    def _is_qualifying_diagnosis(self, icd_code: str) -> bool:
        """Check if the given ICD-10 code qualifies for Heart Failure cohort"""
        return self.reference_service.is_qualifying_diagnosis(icd_code)
    
    def _is_exclusion_diagnosis(self, icd_code: str) -> bool:
        """Check if the given ICD-10 code is in the Heart Failure exclusion list"""
        return self.reference_service.is_exclusion_diagnosis(icd_code)
    
    def _process_risk_variables(self, patient: Patient) -> None:
        """
        Process Heart Failure risk variables for a patient and create summary
        
        Args:
            patient: The patient to process
        """
        # Get all possible Heart Failure risk variables
        all_possible_vars = self.reference_service.get_all_risk_variables()
        
        # Initialize tracking dictionaries
        patient.risk_variables = {
            var: {
                'found': False,
                'row': 0,
                'clean_name': strip_cc_suffix(var)
            } for var in all_possible_vars
        }
        
        patient.seen_risk_variables = {}
        
        # Process each diagnosis to track risk variables
        for dx in patient.diagnoses:
            risk_var = dx.comorbidity_risk_variable
            seq_num = dx.sequence_number
            
            # Skip empty risk variables
            if not risk_var:
                continue
            
            # Check if this is a "Not Present on Admission" risk variable
            not_present = '(Not Present on Admission)' in risk_var
            
            # Remove the "(Not Present on Admission)" suffix if present
            base_risk_var = risk_var.split(' (Not Present on Admission)')[0] if not_present else risk_var
            
            # If it's present on admission, update tracking
            if not not_present:
                # Check if this exact variable name is in our list
                if base_risk_var in patient.risk_variables:
                    # Only update if not found yet or if this is an earlier row
                    if not patient.risk_variables[base_risk_var]['found'] or seq_num < patient.risk_variables[base_risk_var]['row']:
                        patient.risk_variables[base_risk_var]['found'] = True
                        patient.risk_variables[base_risk_var]['row'] = seq_num
            
            # Handle duplicate marking
            if not not_present and base_risk_var in patient.seen_risk_variables:
                # Mark as duplicate
                dx.is_duplicate = True
                dx.first_occurrence_row = patient.seen_risk_variables[base_risk_var]
            elif not not_present:
                # First valid occurrence
                patient.seen_risk_variables[base_risk_var] = seq_num
                dx.is_duplicate = False
                dx.first_occurrence_row = seq_num
        
        # Convert risk variables to summary format
        risk_variables_summary = []
        for var_name, var_info in patient.risk_variables.items():
            risk_variables_summary.append({
                'name': var_name,
                'clean_name': var_info['clean_name'],
                'found': var_info['found'],
                'row': var_info['row']
            })
        
        # Sort alphabetically by the clean name
        risk_variables_summary.sort(key=lambda x: x['clean_name'])
        
        # Store in patient
        patient.risk_variables_summary = risk_variables_summary
    
    def _generate_smart_poa_issues(self, patient: Patient) -> List[Dict]:
        """
        Generate POA issues that are truly problematic for Heart Failure analysis.
        
        Only show risk variables that are POA=N/U AND don't have the same risk variable 
        with POA=Y/E/W in rows 1-25
        
        Args:
            patient: The patient to analyze
            
        Returns:
            List of truly problematic POA issues
        """
        poa_issues = []
        
        # First, collect all risk variables that appear with good POA status in rows 1-25
        good_poa_risk_vars = set()
        for dx in patient.diagnoses:
            if (not dx.is_primary and 
                dx.sequence_number <= 25 and 
                dx.comorbidity_risk_variable and 
                '(Not Present on Admission)' not in dx.comorbidity_risk_variable and
                dx.poa_status in ['Y', 'E', 'W']):
                good_poa_risk_vars.add(dx.comorbidity_risk_variable)
        
        # Now check for problematic POA=N/U cases
        for dx in patient.diagnoses:
            if (not dx.is_primary and 
                dx.comorbidity_risk_variable and 
                '(Not Present on Admission)' in dx.comorbidity_risk_variable):
                
                base_risk_var = dx.comorbidity_risk_variable.split(' (Not Present on Admission)')[0]
                
                # Only flag as problematic if this risk variable doesn't appear 
                # with good POA status elsewhere in rows 1-25
                if base_risk_var not in good_poa_risk_vars:
                    poa_issues.append({
                        'row': dx.sequence_number,
                        'code': dx.icd_code,
                        'risk_variable': base_risk_var
                    })
        
        return poa_issues
    
    def get_analysis_summary(self, patient: Patient) -> Dict:
        """
        Get a comprehensive summary of the Heart Failure analysis for a patient
        
        Args:
            patient: The analyzed patient
            
        Returns:
            Dictionary with analysis summary
        """
        return {
            'patient_id': patient.patient_id,
            'analysis_type': 'Heart Failure Risk Assessment',
            'total_diagnoses': len(patient.diagnoses),
            'primary_diagnosis': {
                'code': patient.get_primary_diagnosis().icd_code if patient.get_primary_diagnosis() else '',
                'poa_status': patient.get_primary_diagnosis().poa_status if patient.get_primary_diagnosis() else '',
                'qualifies_for_hf': self._is_qualifying_diagnosis(patient.get_primary_diagnosis().icd_code) if patient.get_primary_diagnosis() else False
            },
            'cohort_qualification': {
                'qualifies_for_hf_cohort': patient.qualifies_for_hf_cohort,
                'has_exclusion': patient.has_exclusion,
                'exclusion_count': len(patient.exclusion_details)
            },
            'risk_variables': {
                'total_found': patient.get_found_risk_variable_count(),
                'high_row_count': patient.get_high_row_risk_variable_count(),
                'poa_issues': len(patient.risk_poa_issues)
            },
            'comorbidity_status': {
                'mcc_count': len(patient.get_mcc_diagnoses()),
                'cc_count': len(patient.get_cc_diagnoses()),
                'hac_count': len(patient.get_hac_diagnoses()),
                'duplicate_risk_variables': len(patient.get_duplicate_risk_variables())
            },
            'data_quality': {
                'diagnoses_with_poa': len([dx for dx in patient.diagnoses if dx.poa_status]),
                'diagnoses_with_risk_vars': len(patient.get_diagnoses_with_risk_variables()),
                'secondary_diagnoses': len(patient.get_secondary_diagnoses())
            }
        }
    
    def validate_patient_data(self, patient: Patient) -> List[str]:
        """
        Validate patient data for Heart Failure analysis
        
        Args:
            patient: The patient to validate
            
        Returns:
            List of validation warnings/issues
        """
        issues = []
        
        if not patient.diagnoses:
            issues.append("No diagnoses found for patient")
            return issues
        
        primary_dx = patient.get_primary_diagnosis()
        if not primary_dx:
            issues.append("No primary diagnosis found (sequence 1)")
        
        # Check for missing POA indicators
        missing_poa = [dx for dx in patient.diagnoses if not dx.poa_status]
        if missing_poa:
            issues.append(f"{len(missing_poa)} diagnoses missing POA status")
        
        # Check for empty diagnosis codes
        empty_codes = [dx for dx in patient.diagnoses if not dx.icd_code]
        if empty_codes:
            issues.append(f"{len(empty_codes)} diagnoses have empty ICD codes")
        
        # Check if primary diagnosis POA status is appropriate for HF analysis
        if primary_dx and primary_dx.poa_status not in ['Y', 'E']:
            issues.append(f"Primary diagnosis POA status '{primary_dx.poa_status}' may not qualify for HF cohort")
        
        return issues