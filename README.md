# Epic FHIR Integration

Healthcare-focused Epic FHIR integration with bidirectional HL7 messaging, built for clinical workflows and patient safety analytics.

## Quick Start for Epic EHR Launch Testing

### Prerequisites

- Python 3.8+
- OpenSSL (for certificate generation)
- GCP Project with Secret Manager enabled
- Epic sandbox/development client credentials

### 1. Clone and Setup

```bash
git clone <repository-url>
cd epic-fhir-integration

# Install dependencies
pip install -r requirements.txt

# Run automated setup
python setup_local.py
```

### 2. Configure Environment

Update `.env` file with your Epic credentials:

```bash
# Epic Configuration
EPIC_CLIENT_ID_SECRET=your_epic_client_id_secret_name
GCP_PROJECT_ID=your-gcp-project-id

# Generate a secure secret key (32+ characters)
SECRET_KEY=your-very-secure-secret-key-at-least-32-characters-long
```

### 3. Setup GCP Secret Manager

Store your Epic client ID in GCP Secret Manager:

```bash
# Example: Store Epic client ID
gcloud secrets create non_prod_client_id_hyperdrive --data="your-epic-client-id"
```

### 4. Start the Application

```bash
python app.py
```

The application will start on `https://localhost:443`

### 5. Test Epic Launch

1. Navigate to `https://localhost` in your browser
2. Accept the SSL certificate warning (expected for development)
3. Click "Launch with Epic" 
4. Complete Epic OAuth flow

## Missing Files Checklist

If you're migrating from the original single-file structure, ensure you have:

### Required Certificates
- `certs/cert.pem` - SSL certificate for HTTPS
- `certs/key.pem` - SSL private key  
- `keys/private.pem` - JWT signing key for Epic client assertions

### Environment Configuration
- `.env` - Environment variables (created by setup script)

### Templates (Basic Structure)
- `templates/web/base.html` - Base template
- `templates/web/index.html` - Landing page
- `templates/web/menu.html` - Main menu
- `templates/web/error.html` - Error pages

## Epic Integration Requirements

### OAuth2 Callback URL
Configure in Epic: `https://localhost/callback`

### JWKS Endpoint  
Available at: `https://localhost/.well-known/jwks.json`

### Required Scopes
- `openid` - User identification
- `fhirUser` - Epic user context
- `launch` - EHR launch context (for EHR launches)
- `patient/Patient.read` - Patient data access

## Development Features

### Patient Data Access
- FHIR R4 patient search and retrieval
- Epic identifier support (MRN, EPI)
- Comprehensive audit logging

### HL7 Bidirectional Messaging
- Epic getMessage/setMessage endpoints
- ADT^A08 message parsing
- PSI (Patient Safety Indicator) data extraction

### Security & Compliance
- HIPAA-compliant audit logging
- OAuth2 token management with refresh
- Comprehensive error handling
- Security event monitoring

## Troubleshooting

### SSL Certificate Issues
```bash
# Regenerate certificates
rm certs/* keys/*
bash generate_certs.sh
```

### Epic Authentication Errors
1. Verify client ID in GCP Secret Manager
2. Check OAuth callback URL configuration
3. Ensure certificates are properly generated
4. Verify Epic sandbox access

### Token Refresh Issues
1. Check Epic token endpoint configuration
2. Verify JWT signing key exists
3. Review token expiration settings

## File Structure

```
epic-fhir-integration/
├── app/
│   ├── __init__.py           # Flask app factory
│   ├── config.py             # Configuration management
│   ├── auth/                 # OAuth & token management
│   ├── fhir/                 # FHIR API client & routes
│   ├── hl7/                  # HL7 parsing & messaging
│   ├── web/                  # Web interface
│   └── core/                 # Logging, exceptions, secrets
├── templates/                # Jinja2 templates
├── static/                   # CSS, JS, assets
├── certs/                    # SSL certificates (gitignored)
├── keys/                     # JWT signing keys (gitignored)
├── app.py                    # Application entry point
├── setup_local.py            # Local development setup
├── requirements.txt          # Python dependencies
└── .env                      # Environment variables (gitignored)
```

## Configuration

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `SECRET_KEY` | Flask session secret (32+ chars) | Yes |
| `EPIC_BASE_URL` | Epic FHIR server URL | Yes |
| `EPIC_CLIENT_ID_SECRET` | GCP secret name for Epic client ID | Yes |
| `GCP_PROJECT_ID` | Google Cloud project ID | Yes |
| `FLASK_ENV` | Environment (development/production) | No |
| `LOG_LEVEL` | Logging level (INFO/DEBUG/WARNING) | No |

### Epic Sandbox Configuration

For Epic sandbox testing, use:
- **FHIR Server**: `https://vendorservices.epic.com/interconnect-amcurprd-oauth/api/FHIR/R4`
- **Test Patient**: Camila Lopez (ID: `erXuFYUfucBZaryVksYEcMg3`)

## Architecture Principles

This application follows the principle: **"Secure and compliant, not enterprise-ready"**

### Included (Healthcare Focus)
✅ Security event logging  
✅ HIPAA audit trails  
✅ Token security with refresh  
✅ Error handling without PHI leakage  
✅ Input validation for security  
✅ Request correlation for incident investigation  

### Excluded (Enterprise Features)
❌ Performance monitoring/metrics  
❌ Health check endpoints  
❌ Caching systems  
❌ Complex retry logic  
❌ Extensive validation beyond security  
❌ Multiple environment configurations  

## Security Notes

- All patient data access is logged for HIPAA compliance
- OAuth tokens are automatically refreshed
- SSL/TLS required for all communications
- Sensitive data is filtered from logs
- JWT client assertions for Epic authentication

## Support

For issues:
1. Check logs in console output
2. Verify Epic connectivity with API tester
3. Review audit logs for authentication issues
4. Validate configuration with setup script

## License

Healthcare application - use in compliance with HIPAA and applicable regulations.