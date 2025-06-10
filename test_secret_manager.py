#!/usr/bin/env python3
"""
Test script to verify GCP Secret Manager access.
Run this to debug Secret Manager issues.
"""

import os
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

# Load environment
from app.config import load_dotenv_if_exists
load_dotenv_if_exists()

def test_secret_manager():
    """Test GCP Secret Manager connectivity."""
    
    print("🔐 Testing GCP Secret Manager Access")
    print("=" * 50)
    
    # Check environment variables
    project_id = os.getenv('GCP_PROJECT_ID')
    secret_name = os.getenv('EPIC_CLIENT_ID_SECRET')
    
    print(f"Project ID: {project_id}")
    print(f"Secret Name: {secret_name}")
    
    if not project_id:
        print("❌ GCP_PROJECT_ID not set in environment")
        return False
    
    if not secret_name:
        print("❌ EPIC_CLIENT_ID_SECRET not set in environment")
        return False
    
    # Test Secret Manager import
    try:
        from google.cloud import secretmanager
        print("✓ Google Cloud Secret Manager imported successfully")
    except ImportError as e:
        print(f"❌ Failed to import Secret Manager: {e}")
        return False
    
    # Test client creation
    try:
        client = secretmanager.SecretManagerServiceClient()
        print("✓ Secret Manager client created")
    except Exception as e:
        print(f"❌ Failed to create Secret Manager client: {e}")
        print("   Try running: gcloud auth application-default login")
        return False
    
    # Test secret access
    try:
        name = f"projects/{project_id}/secrets/{secret_name}/versions/latest"
        print(f"Attempting to access: {name}")
        
        response = client.access_secret_version(request={"name": name})
        secret_value = response.payload.data.decode("UTF-8")
        
        print("✓ Secret accessed successfully!")
        print(f"Secret value: {secret_value[:8]}...{secret_value[-4:]} ({len(secret_value)} chars)")
        return True
        
    except Exception as e:
        print(f"❌ Failed to access secret: {e}")
        print("\nTroubleshooting steps:")
        print("1. Check if secret exists: gcloud secrets describe " + secret_name)
        print("2. Check permissions: gcloud secrets get-iam-policy " + secret_name)
        print("3. Grant access: gcloud secrets add-iam-policy-binding " + secret_name + " --member=user:YOUR_EMAIL --role=roles/secretmanager.secretAccessor")
        return False

def test_application_integration():
    """Test the application's Secret Manager integration."""
    
    print("\n🔧 Testing Application Integration")
    print("=" * 50)
    
    try:
        from app.core.secrets import get_secret_manager
        secret_manager = get_secret_manager()
        print("✓ Application secret manager initialized")
        
        secret_name = os.getenv('EPIC_CLIENT_ID_SECRET')
        client_id = secret_manager.get_secret(secret_name)
        
        print("✓ Secret retrieved through application")
        print(f"Client ID: {client_id[:8]}...{client_id[-4:]} ({len(client_id)} chars)")
        return True
        
    except Exception as e:
        print(f"❌ Application integration failed: {e}")
        return False

if __name__ == "__main__":
    success1 = test_secret_manager()
    success2 = test_application_integration() if success1 else False
    
    print("\n" + "=" * 50)
    if success1 and success2:
        print("✅ All tests passed! Secret Manager is working correctly.")
        print("You can now restart your application.")
    else:
        print("❌ Some tests failed. Please fix the issues above.")
        
        print("\nQuick fix commands:")
        project_id = os.getenv('GCP_PROJECT_ID', 'smart-test-443717')
        secret_name = os.getenv('EPIC_CLIENT_ID_SECRET', 'non_prod_client_id_hyperdrive')
        
        print(f"# Check if secret exists:")
        print(f"gcloud secrets describe {secret_name}")
        print(f"")
        print(f"# Create secret if missing:")
        print(f"gcloud secrets create {secret_name} --data='787b6b00-c1d5-40be-bd24-2830ef7cc087'")
        print(f"")
        print(f"# Grant yourself access:")
        print(f"gcloud projects add-iam-policy-binding {project_id} --member=user:$(gcloud auth list --filter=status:ACTIVE --format='value(account)') --role=roles/secretmanager.secretAccessor")
        print(f"")
        print(f"# Set up application default credentials:")
        print(f"gcloud auth application-default login")