from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set

@dataclass
class Diagnosis:
    """Represents a single diagnosis code for Heart Failure analysis"""
    sequence_number: int
    icd_code: str
    poa_status: str = ""  # Y, N, U, E, W
    
    # Analysis results (populated by AnalysisService)
    comorbidity_risk_variable: str = ""
    models: str = ""  # HWM, HWR, M, R
    mcc_cc_status: str = ""  # MCC, CC, HAC, or empty
    
    # Duplicate tracking
    is_duplicate: bool = False
    first_occurrence_row: Optional[int] = None
    
    @property
    def is_primary(self) -> bool:
        """Returns True if this is a primary diagnosis (sequence 1)"""
        return self.sequence_number == 1
    
    @property
    def is_present_on_admission(self) -> bool:
        """Returns True if POA status indicates present on admission"""
        return self.poa_status in ['Y', 'E', 'W']
    
    @property
    def is_not_present_on_admission(self) -> bool:
        """Returns True if POA status indicates NOT present on admission"""
        return self.poa_status in ['N', 'U']

@dataclass
class Patient:
    """Represents a patient with diagnoses for Heart Failure analysis"""
    patient_id: str
    name: str = ""  # Keep empty for PHI compliance
    diagnoses: List[Diagnosis] = field(default_factory=list)
    
    # Heart Failure analysis results (populated by AnalysisService)
    qualifies_for_hf_cohort: bool = False
    has_exclusion: bool = False
    exclusion_details: List[Dict] = field(default_factory=list)
    risk_poa_issues: List[Dict] = field(default_factory=list)
    risk_variables_summary: List[Dict] = field(default_factory=list)
    
    # Risk variables tracking (internal use)
    risk_variables: Dict[str, Dict] = field(default_factory=dict)
    seen_risk_variables: Dict[str, int] = field(default_factory=dict)
    
    def add_diagnosis(self, diagnosis: Diagnosis) -> None:
        """Add a diagnosis to this patient"""
        self.diagnoses.append(diagnosis)
    
    def get_primary_diagnosis(self) -> Optional[Diagnosis]:
        """Get the primary diagnosis (sequence 1)"""
        for dx in self.diagnoses:
            if dx.is_primary:
                return dx
        return None
    
    def get_diagnoses_by_poa_status(self, poa_status: str) -> List[Diagnosis]:
        """Get all diagnoses with specific POA status"""
        return [dx for dx in self.diagnoses if dx.poa_status == poa_status]
    
    def get_secondary_diagnoses(self) -> List[Diagnosis]:
        """Get all secondary diagnoses (sequence > 1)"""
        return [dx for dx in self.diagnoses if not dx.is_primary]
    
    def get_found_risk_variable_count(self) -> int:
        """Get count of found risk variables"""
        return sum(1 for var in self.risk_variables_summary if var.get('found', False))
    
    def get_high_row_risk_variable_count(self) -> int:
        """Get count of risk variables first appearing in row 26+"""
        return len([
            var for var in self.risk_variables_summary 
            if var.get('found', False) and var.get('row', 0) >= 26
        ])
    
    def get_risk_variables_in_high_rows(self) -> List[Dict]:
        """Get risk variables that first appear in row 26 or higher"""
        return [
            var for var in self.risk_variables_summary 
            if var.get('found', False) and var.get('row', 0) >= 26
        ]
    
    def has_diagnosis_code(self, icd_code: str) -> bool:
        """Check if patient has a specific diagnosis code"""
        from app.utils.code_utils import normalize_icd_code
        
        normalized_target = normalize_icd_code(icd_code)
        return any(
            normalize_icd_code(dx.icd_code) == normalized_target 
            for dx in self.diagnoses
        )
    
    def get_diagnoses_with_risk_variables(self) -> List[Diagnosis]:
        """Get all diagnoses that have assigned risk variables"""
        return [
            dx for dx in self.diagnoses 
            if dx.comorbidity_risk_variable and not dx.is_primary
        ]
    
    def get_duplicate_risk_variables(self) -> List[Diagnosis]:
        """Get all diagnoses marked as duplicate risk variables"""
        return [dx for dx in self.diagnoses if dx.is_duplicate]
    
    def get_mcc_diagnoses(self) -> List[Diagnosis]:
        """Get all diagnoses marked as MCC"""
        return [dx for dx in self.diagnoses if dx.mcc_cc_status == 'MCC']
    
    def get_cc_diagnoses(self) -> List[Diagnosis]:
        """Get all diagnoses marked as CC"""
        return [dx for dx in self.diagnoses if dx.mcc_cc_status == 'CC']
    
    def get_hac_diagnoses(self) -> List[Diagnosis]:
        """Get all diagnoses marked as HAC"""
        return [dx for dx in self.diagnoses if dx.mcc_cc_status == 'HAC']
    
    def get_analysis_summary(self) -> Dict:
        """Get a summary of the Heart Failure analysis"""
        return {
            'patient_id': self.patient_id,
            'total_diagnoses': len(self.diagnoses),
            'qualifies_for_hf_cohort': self.qualifies_for_hf_cohort,
            'has_exclusion': self.has_exclusion,
            'exclusion_count': len(self.exclusion_details),
            'risk_variables_found': self.get_found_risk_variable_count(),
            'high_row_risk_variables': self.get_high_row_risk_variable_count(),
            'poa_issues': len(self.risk_poa_issues),
            'mcc_count': len(self.get_mcc_diagnoses()),
            'cc_count': len(self.get_cc_diagnoses()),
            'hac_count': len(self.get_hac_diagnoses()),
            'duplicate_risk_variables': len(self.get_duplicate_risk_variables())
        }
    
    def __str__(self) -> str:
        """String representation for debugging (PHI-safe)"""
        return f"Patient(id={self.patient_id}, diagnoses={len(self.diagnoses)}, hf_qualified={self.qualifies_for_hf_cohort})"