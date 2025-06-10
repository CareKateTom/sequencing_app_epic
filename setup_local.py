#!/usr/bin/env python3
"""
Local development setup script for Epic FHIR Integration.

Sets up certificates, environment, and validates configuration.
"""

import os
import sys
import subprocess
from pathlib import Path


def create_directories():
    """Create necessary directories."""
    dirs = ['certs', 'keys', 'logs', 'static/css', 'static/js', 'templates/web', 'templates/fhir', 'templates/hl7', 'templates/auth']
    
    for dir_path in dirs:
        Path(dir_path).mkdir(parents=True, exist_ok=True)
        print(f"✓ Created directory: {dir_path}")


def generate_certificates():
    """Generate SSL certificates and JWT signing keys."""
    print("\n🔐 Generating SSL certificates...")
    
    # Check if certificates already exist
    if Path('certs/cert.pem').exists() and Path('certs/key.pem').exists():
        print("✓ SSL certificates already exist")
    else:
        try:
            # Generate SSL private key
            subprocess.run([
                'openssl', 'genrsa', '-out', 'certs/key.pem', '2048'
            ], check=True, capture_output=True)
            
            # Generate SSL certificate
            subprocess.run([
                'openssl', 'req', '-new', '-x509', '-key', 'certs/key.pem', 
                '-out', 'certs/cert.pem', '-days', '365',
                '-subj', '/C=US/ST=IL/L=Chicago/O=Epic FHIR Integration/CN=localhost'
            ], check=True, capture_output=True)
            
            print("✓ SSL certificates generated")
            
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to generate SSL certificates: {e}")
            return False
        except FileNotFoundError:
            print("❌ OpenSSL not found. Please install OpenSSL to generate certificates.")
            return False
    
    # Generate JWT signing key
    if Path('keys/private.pem').exists():
        print("✓ JWT signing key already exists")
    else:
        try:
            subprocess.run([
                'openssl', 'genrsa', '-out', 'keys/private.pem', '2048'
            ], check=True, capture_output=True)
            print("✓ JWT signing key generated")
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to generate JWT signing key: {e}")
            return False
    
    # Set appropriate permissions
    try:
        os.chmod('certs/key.pem', 0o600)
        os.chmod('keys/private.pem', 0o600)
        os.chmod('certs/cert.pem', 0o644)
        print("✓ Certificate permissions set")
    except Exception as e:
        print(f"⚠️  Warning: Could not set certificate permissions: {e}")
    
    return True


def create_env_file():
    """Create .env file if it doesn't exist."""
    env_file = Path('.env')
    
    if env_file.exists():
        print("✓ .env file already exists")
        return
    
    env_content = """# Flask Configuration
SECRET_KEY=your-secret-key-change-in-production-at-least-32-chars-long
FLASK_ENV=development
FLASK_DEBUG=True

# Epic FHIR Configuration
EPIC_BASE_URL=https://vendorservices.epic.com/interconnect-amcurprd-oauth/api/FHIR/R4
EPIC_CLIENT_ID_SECRET=non_prod_client_id_hyperdrive

# GCP Configuration (update with your project)
GCP_PROJECT_ID=your-gcp-project-id

# Application Settings
LOG_LEVEL=INFO
SESSION_TIMEOUT_HOURS=8

# SSL Configuration
SSL_CERT_PATH=certs/cert.pem
SSL_KEY_PATH=certs/key.pem

# Development Server Settings
HOST=localhost
PORT=443
"""
    
    env_file.write_text(env_content)
    print("✓ Created .env file (please update with your values)")


def validate_requirements():
    """Check if required packages are installed."""
    print("\n📦 Checking Python requirements...")
    
    try:
        import flask
        print(f"✓ Flask {flask.__version__}")
    except ImportError:
        print("❌ Flask not installed")
        return False
    
    try:
        import requests
        print(f"✓ Requests {requests.__version__}")
    except ImportError:
        print("❌ Requests not installed")
        return False
    
    try:
        import google.cloud.secretmanager
        print("✓ Google Cloud Secret Manager")
    except ImportError:
        print("❌ Google Cloud Secret Manager not installed")
        return False
    
    try:
        import jwt
        print("✓ PyJWT")
    except ImportError:
        print("❌ PyJWT not installed")
        return False
    
    try:
        import cryptography
        print("✓ Cryptography")
    except ImportError:
        print("❌ Cryptography not installed")
        return False
    
    return True


def validate_configuration():
    """Validate the application configuration."""
    print("\n⚙️  Validating configuration...")
    
    # Load environment
    from app.config import load_dotenv_if_exists, validate_environment
    
    load_dotenv_if_exists()
    
    if validate_environment():
        print("✓ Environment variables valid")
    else:
        print("❌ Environment validation failed")
        return False
    
    # Check certificate files
    required_files = [
        'certs/cert.pem',
        'certs/key.pem', 
        'keys/private.pem'
    ]
    
    for file_path in required_files:
        if Path(file_path).exists():
            print(f"✓ {file_path}")
        else:
            print(f"❌ {file_path} missing")
            return False
    
    return True


def main():
    """Main setup function."""
    print("🏥 Epic FHIR Integration - Local Development Setup")
    print("=" * 55)
    
    # Check Python version
    if sys.version_info < (3, 8):
        print("❌ Python 3.8+ required")
        sys.exit(1)
    
    print(f"✓ Python {sys.version.split()[0]}")
    
    # Create directories
    print("\n📁 Creating directories...")
    create_directories()
    
    # Generate certificates
    if not generate_certificates():
        print("\n❌ Certificate generation failed. You may need to install OpenSSL.")
        print("Alternatively, you can run the generate_certs.sh script manually.")
    
    # Create environment file
    print("\n🔧 Setting up environment...")
    create_env_file()
    
    # Validate requirements
    if not validate_requirements():
        print("\n❌ Missing required packages. Install with:")
        print("pip install -r requirements.txt")
        sys.exit(1)
    
    # Validate configuration
    if not validate_configuration():
        print("\n❌ Configuration validation failed.")
        print("Please check your .env file and certificate files.")
        sys.exit(1)
    
    print("\n" + "=" * 55)
    print("✅ Local development setup complete!")
    print("\nNext steps:")
    print("1. Update .env file with your Epic client ID secret")
    print("2. Update GCP_PROJECT_ID in .env file")
    print("3. Ensure GCP credentials are configured")
    print("4. Run: python app.py")
    print("5. Navigate to: https://localhost")
    print("\nNote: Your browser will show a security warning for the")
    print("self-signed certificate. This is expected for development.")


if __name__ == '__main__':
    main()