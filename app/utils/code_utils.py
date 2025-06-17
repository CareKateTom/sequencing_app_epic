import re
from typing import Optional

def clean_icd_code(code: Optional[str]) -> str:
    """
    Remove any decimal points from ICD-10 codes.
    Example: 'I50.1' -> 'I501'
    
    Args:
        code: ICD-10 diagnosis code
        
    Returns:
        Cleaned code with decimal points removed
    """
    if not code:
        return ''
    # Strip whitespace and remove decimal points
    return re.sub(r'\.', '', code.strip())

def strip_cc_suffix(risk_var: str) -> str:
    """
    Strip the "(CC ##)" suffix from risk variable names for cleaner display in summary.
    For example: "Congestive Heart Failure (CC 85)" -> "Congestive Heart Failure"
    
    Args:
        risk_var: Risk variable name
        
    Returns:
        Risk variable name without CC suffix
    """
    if risk_var and " (CC " in risk_var:
        # Find the index where the pattern starts
        pattern_index = risk_var.find(" (CC ")
        if pattern_index > 0:
            # Return the string up to the pattern
            return risk_var[:pattern_index]
    # Return the original string if no pattern is found
    return risk_var