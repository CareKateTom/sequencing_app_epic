import os
import csv
import re
from typing import Dict, List, Optional, Set
from flask import current_app

from app.utils.code_utils import clean_icd_code

class ReferenceService:
    """Service for loading and accessing Heart Failure reference data"""
    
    def __init__(self):
        """Initialize without loading data - data will be loaded on first access"""
        self._reference_dir = None
        self._data_loaded = False
        
        # Initialize empty data structures
        self.qualifying_codes = []
        self.exclusion_codes = []
        self.risk_mapping = {}
        self.mcc_list = []
        self.cc_list = []
        self.hac_list = []
        
        # Cache for risk variables
        self._all_risk_variables = None
    
    def _ensure_data_loaded(self):
        """Ensure reference data is loaded (lazy loading with app context)"""
        if self._data_loaded:
            return
            
        # Get reference directory from app config or use default
        if current_app:
            self._reference_dir = current_app.config.get('REFERENCE_DIR', 'reference_files')
        else:
            self._reference_dir = 'reference_files'
        
        # Load all reference data
        self.qualifying_codes = self._load_qualifying_codes()
        self.exclusion_codes = self._load_exclusion_codes()
        self.risk_mapping = self._load_risk_crosswalk()
        self.mcc_list = self._load_mcc_list()
        self.cc_list = self._load_cc_list()
        self.hac_list = self._load_hac_list()
        
        self._data_loaded = True
    
    def _load_csv_data(self, filename: str, preprocessing_func=None) -> List:
        """Generic function to load data from CSV files"""
        filepath = os.path.join(self._reference_dir, filename)
        try:
            result = []
            with open(filepath, 'r', encoding='utf-8-sig') as file:
                reader = csv.reader(file)
                # Skip header if it exists
                headers = next(reader, None)
                
                # Process rows
                for row in reader:
                    if row and row[0].strip():  # Ensure row exists and has a non-empty first column
                        if preprocessing_func:
                            processed_row = preprocessing_func(row)
                            if processed_row is not None:  # Allow preprocessing to filter rows
                                result.append(processed_row)
                        else:
                            result.append(clean_icd_code(row[0]))
            
            return result
        except FileNotFoundError:
            print(f"Warning: File not found at {filepath}")
            return []
        except Exception as e:
            print(f"Error loading data from {filepath}: {e}")
            return []
    
    def _load_qualifying_codes(self, filename='hf_qualifying_codes.csv') -> List[str]:
        """Load Heart Failure qualifying diagnosis codes"""
        return self._load_csv_data(filename)
    
    def _load_exclusion_codes(self, filename='hf_exclusion_codes.csv') -> List[str]:
        """Load Heart Failure exclusion diagnosis codes"""
        return self._load_csv_data(filename)
    
    def _load_risk_crosswalk(self, filename='2025_HF_Crosswalk.csv') -> Dict:
        """Load Heart Failure risk variable crosswalk mappings with POA requirements"""
        def process_crosswalk_row(row):
            if len(row) >= 4:  # Expecting 4 columns: ICD, Risk Variable, Models, POA
                icd_code = clean_icd_code(row[0])
                risk_variable = row[1].strip()
                models = row[2].strip() if len(row) >= 3 else ""
                poa_required = row[3].strip().upper() if len(row) >= 4 else "Y"  # Default to Y if missing
                
                return {icd_code: {
                    "risk_variable": risk_variable, 
                    "models": models,
                    "poa_required": poa_required  # Y = POA required, N = POA not required
                }}
            elif len(row) >= 3:  # Fallback for old format without POA column
                icd_code = clean_icd_code(row[0])
                risk_variable = row[1].strip()
                models = row[2].strip()
                
                return {icd_code: {
                    "risk_variable": risk_variable, 
                    "models": models,
                    "poa_required": "Y"  # Default to requiring POA for backward compatibility
                }}
            return None
        
        # Build dictionary from list of individual mappings
        risk_mapping = {}
        result = self._load_csv_data(filename, process_crosswalk_row)
        for item in result:
            if item:  # Skip None results
                risk_mapping.update(item)
        return risk_mapping
    
    def _load_mcc_list(self, filename='MCC_List.csv') -> List[str]:
        """Load Major Complication/Comorbidity (MCC) diagnosis codes"""
        return self._load_csv_data(filename)
    
    def _load_cc_list(self, filename='CC_List.csv') -> List[str]:
        """Load Complication/Comorbidity (CC) diagnosis codes"""
        return self._load_csv_data(filename)
    
    def _load_hac_list(self, filename='2025_CMS_HAC_List.csv') -> List[str]:
        """Load Hospital Acquired Condition (HAC) diagnosis codes"""
        return self._load_csv_data(filename)
    
    def is_qualifying_diagnosis(self, icd_code: str) -> bool:
        """Check if the given ICD-10 code qualifies for Heart Failure cohort"""
        self._ensure_data_loaded()
        if not icd_code:
            return False
        # Strip any whitespace, convert to uppercase, and remove decimals for comparison
        cleaned_code = clean_icd_code(icd_code).upper()
        return cleaned_code in [code.upper() for code in self.qualifying_codes]
    
    def is_exclusion_diagnosis(self, icd_code: str) -> bool:
        """Check if the given ICD-10 code is in the Heart Failure exclusion list"""
        self._ensure_data_loaded()
        if not icd_code:
            return False
        # Strip any whitespace, convert to uppercase, and remove decimals for comparison
        cleaned_code = clean_icd_code(icd_code).upper()
        return cleaned_code in [code.upper() for code in self.exclusion_codes]
    
    def is_mcc(self, icd_code: str) -> bool:
        """Check if the given ICD-10 code is in the MCC list"""
        self._ensure_data_loaded()
        if not icd_code:
            return False
        # Strip any whitespace, convert to uppercase, and remove decimals for comparison
        cleaned_code = clean_icd_code(icd_code).upper()
        return cleaned_code in [code.upper() for code in self.mcc_list]
    
    def is_cc(self, icd_code: str) -> bool:
        """Check if the given ICD-10 code is in the CC list"""
        self._ensure_data_loaded()
        if not icd_code:
            return False
        # Strip any whitespace, convert to uppercase, and remove decimals for comparison
        cleaned_code = clean_icd_code(icd_code).upper()
        return cleaned_code in [code.upper() for code in self.cc_list]
    
    def is_hac(self, icd_code: str) -> bool:
        """Check if the given ICD-10 code is in the HAC list"""
        self._ensure_data_loaded()
        if not icd_code:
            return False
        # Strip any whitespace, convert to uppercase, and remove decimals for comparison
        cleaned_code = clean_icd_code(icd_code).upper()
        return cleaned_code in [code.upper() for code in self.hac_list]
    
    def get_risk_variable(self, icd_code: str) -> Optional[Dict]:
        """Get Heart Failure risk variable information for a diagnosis code"""
        self._ensure_data_loaded()
        if not icd_code:
            return None
        
        # Clean the code for comparison - remove decimals and convert to uppercase
        cleaned_code = clean_icd_code(icd_code).upper()
        
        # Check if code exists in the risk mapping
        for code, info in self.risk_mapping.items():
            if cleaned_code == code.upper():
                return info
        
        return None
    
    def get_all_risk_variables(self) -> List[str]:
        """Get all unique Heart Failure risk variables from the risk crosswalk"""
        self._ensure_data_loaded()
        # Use cached list if available
        if self._all_risk_variables is not None:
            return self._all_risk_variables
        
        # Extract all unique risk variables
        risk_variables = set()
        for var_info in self.risk_mapping.values():
            if var_info["risk_variable"]:  # Only add non-empty variables
                risk_variables.add(var_info["risk_variable"])
        
        # Sort and cache
        self._all_risk_variables = sorted(list(risk_variables))
        return self._all_risk_variables
    
    def get_data_summary(self) -> Dict[str, int]:
        """Get summary of loaded reference data for debugging/validation"""
        self._ensure_data_loaded()
        return {
            'qualifying_codes': len(self.qualifying_codes),
            'exclusion_codes': len(self.exclusion_codes),
            'risk_mappings': len(self.risk_mapping),
            'mcc_codes': len(self.mcc_list),
            'cc_codes': len(self.cc_list),
            'hac_codes': len(self.hac_list),
            'unique_risk_variables': len(self.get_all_risk_variables())
        }