#!/usr/bin/env python3
"""
Verify that all required files and functions exist for Epic FHIR Integration.
"""

import os
import sys
from pathlib import Path

def check_files():
    """Check if required files exist."""
    required_files = [
        'app.py',
        'app/__init__.py',
        'app/config.py',
        'app/auth/decorators.py',
        'app/fhir/client.py',
        'app/fhir/metadata.py',
        'app/hl7/routes.py',
        'app/hl7/parser.py',
        'app/web/routes.py',
        'app/core/logging.py',
        'app/core/exceptions.py',
        'app/core/secrets.py',
        'certs/cert.pem',
        'certs/key.pem',
        'keys/private.pem',
        '.env'
    ]
    
    missing_files = []
    for file_path in required_files:
        if not Path(file_path).exists():
            missing_files.append(file_path)
        else:
            print(f"✓ {file_path}")
    
    if missing_files:
        print(f"\n❌ Missing files:")
        for file_path in missing_files:
            print(f"   {file_path}")
        return False
    
    return True

def check_functions():
    """Check if required functions exist in files."""
    print("\n🔍 Checking function definitions...")
    
    # Check auth decorators
    try:
        with open('app/auth/decorators.py', 'r') as f:
            content = f.read()
            
        functions_to_check = [
            'def optional_authentication(',
            'def get_current_user_info(',
            'def require_valid_token(',
            'def is_authenticated('
        ]
        
        for func in functions_to_check:
            if func in content:
                print(f"✓ Found {func.split('(')[0].replace('def ', '')}")
            else:
                print(f"❌ Missing {func.split('(')[0].replace('def ', '')}")
                
    except FileNotFoundError:
        print("❌ app/auth/decorators.py not found")
        return False
    
    # Check FHIR client
    try:
        with open('app/fhir/client.py', 'r') as f:
            content = f.read()
            
        if 'self.session = requests.Session()' in content:
            print("✓ FHIRClient has session attribute")
        else:
            print("❌ FHIRClient missing session attribute")
            
        if 'def search_patients_by_name(' in content:
            print("✓ Found search_patients_by_name function")
        else:
            print("❌ Missing search_patients_by_name function")
            
        if 'def _build_headers(' in content:
            print("✓ Found _build_headers method")
        else:
            print("❌ Missing _build_headers method")
            
    except FileNotFoundError:
        print("❌ app/fhir/client.py not found")
        return False
    
    return True

def check_environment():
    """Check environment configuration."""
    print("\n🔧 Checking environment...")
    
    if not Path('.env').exists():
        print("❌ .env file missing")
        return False
    
    required_vars = [
        'SECRET_KEY',
        'EPIC_BASE_URL',
        'EPIC_CLIENT_ID_SECRET',
        'GCP_PROJECT_ID'
    ]
    
    with open('.env', 'r') as f:
        env_content = f.read()
    
    for var in required_vars:
        if f'{var}=' in env_content:
            print(f"✓ {var} configured")
        else:
            print(f"❌ {var} missing from .env")
    
    return True

def main():
    """Main verification function."""
    print("🏥 Epic FHIR Integration - Setup Verification")
    print("=" * 50)
    
    print("\n📁 Checking required files...")
    files_ok = check_files()
    
    functions_ok = check_functions()
    
    env_ok = check_environment()
    
    print("\n" + "=" * 50)
    if files_ok and functions_ok and env_ok:
        print("✅ All checks passed! Ready for Epic launch testing.")
        print("\nTo start the application:")
        print("python app.py")
        print("\nThen navigate to: https://localhost")
    else:
        print("❌ Some checks failed. Please review the issues above.")
        print("\nYou may need to:")
        print("1. Run setup_local.py")
        print("2. Add missing functions to existing files")
        print("3. Configure your .env file properly")

if __name__ == '__main__':
    main()