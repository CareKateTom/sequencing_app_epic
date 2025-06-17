from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set

@dataclass
class Diagnosis:
    """Represents a single diagnosis code"""
    sequence_number: int
    icd_code: str
    poa_status: str
    comorbidity_risk_variable: str = ""
    models: str = ""
    mcc_cc_status: str = ""
    is_duplicate: bool = False
    first_occurrence_row: Optional[int] = None
    
    @property
    def is_primary(self) -> bool:
        """Returns True if this is a primary diagnosis"""
        return self.sequence_number == 1

@dataclass
class Patient:
    """Represents a patient with diagnoses"""
    patient_id: str
    name: str = ""
    diagnoses: List[Diagnosis] = field(default_factory=list)
    
    # Analysis results
    qualifies_for_hf_cohort: bool = False
    has_exclusion: bool = False
    exclusion_details: List[Dict] = field(default_factory=list)
    risk_poa_issues: List[Dict] = field(default_factory=list)
    risk_variables_summary: List[Dict] = field(default_factory=list)
    
    # Risk variables tracked by row number
    risk_variables: Dict[str, Dict] = field(default_factory=dict)
    
    # Track seen risk variables for duplicate detection
    seen_risk_variables: Dict[str, int] = field(default_factory=dict)
    
    def add_diagnosis(self, diagnosis: Diagnosis) -> None:
        """Add a diagnosis to this patient"""
        self.diagnoses.append(diagnosis)
    
    def get_primary_diagnosis(self) -> Optional[Diagnosis]:
        """Get the primary diagnosis"""
        for dx in self.diagnoses:
            if dx.sequence_number == 1:
                return dx
        return None
    
    def get_risk_variables_in_high_rows(self) -> List[Dict]:
        """Get risk variables that first appear in row 26 or higher"""
        return [
            var for var in self.risk_variables_summary 
            if var.get('found', False) and var.get('row', 0) >= 26
        ]
    
    def get_found_risk_variable_count(self) -> int:
        """Get count of found risk variables"""
        return sum(1 for var in self.risk_variables_summary if var.get('found', False))
    
    def get_high_row_risk_variable_count(self) -> int:
        """Get count of risk variables in high rows"""
        return len(self.get_risk_variables_in_high_rows())