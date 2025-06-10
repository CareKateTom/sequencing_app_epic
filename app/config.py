"""
Configuration management for Epic FHIR Integration application.

Healthcare-focused configuration prioritizing security and compliance.
Follows principle: "Secure and compliant, not enterprise-ready"
"""

import os
from typing import Optional, Tuple
from pathlib import Path


class ConfigError(Exception):
    """Raised when configuration is invalid or missing required values."""
    pass


class Config:
    """
    Simple, secure configuration for healthcare applications.
    
    Focuses on security defaults, compliance requirements, and required settings.
    No enterprise features - just what healthcare apps need.
    """
    
    def __init__(self):
        """Initialize and validate configuration."""
        self._load_environment()
        self._set_security_defaults()
        self._validate_required()
        self._validate_security()
    
    def _load_environment(self):
        """Load configuration from environment variables."""
        
        # Required Settings
        self.SECRET_KEY = self._get_required('SECRET_KEY')
        self.EPIC_BASE_URL = self._get_required('EPIC_BASE_URL')
        self.EPIC_CLIENT_ID_SECRET = self._get_required('EPIC_CLIENT_ID_SECRET')
        self.GCP_PROJECT_ID = self._get_required('GCP_PROJECT_ID')
        
        # Environment Settings
        self.FLASK_ENV = os.getenv('FLASK_ENV', 'production')
        self.FLASK_DEBUG = self._get_bool('FLASK_DEBUG', False)
        
        # Server Settings
        self.HOST = os.getenv('HOST', 'localhost')
        self.PORT = self._get_int('PORT', 443)
        
        # SSL Configuration (required for healthcare)
        self.SSL_CERT_PATH = os.getenv('SSL_CERT_PATH', 'certs/cert.pem')
        self.SSL_KEY_PATH = os.getenv('SSL_KEY_PATH', 'certs/key.pem')
        
        # Healthcare Compliance Settings
        self.LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO').upper()
        self.SESSION_TIMEOUT_HOURS = self._get_int('SESSION_TIMEOUT_HOURS', 8)
        self.AUDIT_LOG_LEVEL = os.getenv('AUDIT_LOG_LEVEL', 'INFO').upper()
        
        # Optional Settings
        self.DATABASE_URL = os.getenv('DATABASE_URL')
        self.REDIS_URL = os.getenv('REDIS_URL')
    
    def _set_security_defaults(self):
        """Set security defaults for healthcare compliance."""
        
        # Force production security in non-development
        if self.FLASK_ENV != 'development':
            self.FLASK_DEBUG = False
        
        # Session security for healthcare
        self.SESSION_COOKIE_SECURE = True
        self.SESSION_COOKIE_HTTPONLY = True
        self.SESSION_COOKIE_SAMESITE = 'Lax'
        self.PERMANENT_SESSION_LIFETIME = self.SESSION_TIMEOUT_HOURS * 3600
        
        # Security headers
        self.SEND_FILE_MAX_AGE_DEFAULT = 0  # No caching of sensitive files
    
    def _validate_required(self):
        """Validate required settings for healthcare applications."""
        
        # Validate Epic URL format
        if not self.EPIC_BASE_URL.startswith(('http://', 'https://')):
            raise ConfigError(f"EPIC_BASE_URL must be a valid URL: {self.EPIC_BASE_URL}")
        
        # Validate secret key security
        if len(self.SECRET_KEY) < 32:
            raise ConfigError("SECRET_KEY must be at least 32 characters for healthcare security")
        
        # Validate log levels
        valid_levels = {'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'}
        if self.LOG_LEVEL not in valid_levels:
            raise ConfigError(f"LOG_LEVEL must be one of {valid_levels}")
        if self.AUDIT_LOG_LEVEL not in valid_levels:
            raise ConfigError(f"AUDIT_LOG_LEVEL must be one of {valid_levels}")
        
        # Validate session timeout
        if not (1 <= self.SESSION_TIMEOUT_HOURS <= 24):
            raise ConfigError("SESSION_TIMEOUT_HOURS must be between 1 and 24 for security")
        
        # Validate port
        if not (1 <= self.PORT <= 65535):
            raise ConfigError(f"PORT must be between 1 and 65535: {self.PORT}")
    
    def _validate_security(self):
        """Validate security requirements for healthcare."""
        
        # Require SSL in production
        if self.FLASK_ENV == 'production':
            if not self._ssl_files_exist():
                raise ConfigError("SSL certificate files required in production for healthcare compliance")
            
            # Require HTTPS in production Epic URL
            if not self.EPIC_BASE_URL.startswith('https://'):
                raise ConfigError("EPIC_BASE_URL must use HTTPS in production")
    
    def _get_required(self, key: str) -> str:
        """Get required environment variable."""
        value = os.getenv(key)
        if not value:
            raise ConfigError(f"Required environment variable '{key}' is not set")
        return value
    
    def _get_bool(self, key: str, default: bool = False) -> bool:
        """Get boolean environment variable."""
        value = os.getenv(key, '').lower()
        if value in ('true', '1', 'yes', 'on'):
            return True
        elif value in ('false', '0', 'no', 'off'):
            return False
        return default
    
    def _get_int(self, key: str, default: int) -> int:
        """Get integer environment variable."""
        value = os.getenv(key)
        if value is None:
            return default
        
        try:
            return int(value)
        except ValueError:
            raise ConfigError(f"Environment variable '{key}' must be an integer: {value}")
    
    def _ssl_files_exist(self) -> bool:
        """Check if SSL certificate files exist."""
        cert_path = Path(self.SSL_CERT_PATH)
        key_path = Path(self.SSL_KEY_PATH)
        return cert_path.exists() and key_path.exists()
    
    def get_ssl_context(self) -> Optional[Tuple[str, str]]:
        """Get SSL context for Flask if certificates exist."""
        if self._ssl_files_exist():
            return (self.SSL_CERT_PATH, self.SSL_KEY_PATH)
        return None
    
    @property
    def is_development(self) -> bool:
        """Check if running in development mode."""
        return self.FLASK_ENV == 'development'
    
    @property
    def is_production(self) -> bool:
        """Check if running in production mode."""
        return self.FLASK_ENV == 'production'
    
    @property
    def requires_ssl(self) -> bool:
        """Check if SSL is required (always True for healthcare)."""
        return True  # Healthcare apps always require SSL
    
    def __repr__(self) -> str:
        """Safe representation (excludes sensitive data)."""
        safe_attrs = [
            'FLASK_ENV', 'HOST', 'PORT', 'LOG_LEVEL', 
            'SESSION_TIMEOUT_HOURS', 'AUDIT_LOG_LEVEL'
        ]
        attrs = [f"{attr}={getattr(self, attr)!r}" for attr in safe_attrs]
        return f"<Config({', '.join(attrs)})>"


def load_config() -> Config:
    """
    Load and validate configuration for Epic FHIR Integration.
    
    Returns:
        Validated configuration instance
        
    Raises:
        ConfigError: If configuration is invalid
    """
    return Config()


def validate_environment() -> bool:
    """
    Validate that all required environment variables are set.
    
    Returns:
        True if environment is valid, False otherwise
    """
    required_vars = [
        'SECRET_KEY',
        'EPIC_BASE_URL', 
        'EPIC_CLIENT_ID_SECRET',
        'GCP_PROJECT_ID'
    ]
    
    missing = [var for var in required_vars if not os.getenv(var)]
    
    if missing:
        print(f"Missing required environment variables: {', '.join(missing)}")
        return False
    
    return True


def load_dotenv_if_exists(dotenv_path: str = '.env') -> bool:
    """
    Load .env file if it exists (simple implementation).
    
    Args:
        dotenv_path: Path to .env file
        
    Returns:
        True if file was loaded, False otherwise
    """
    env_file = Path(dotenv_path)
    
    if not env_file.exists():
        return False
    
    try:
        with open(env_file, 'r') as f:
            for line in f:
                line = line.strip()
                
                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue
                
                # Parse KEY=VALUE
                if '=' in line:
                    key, value = line.split('=', 1)
                    key = key.strip()
                    value = value.strip().strip('"').strip("'")
                    
                    # Only set if not already in environment
                    if key not in os.environ:
                        os.environ[key] = value
        
        return True
        
    except Exception as e:
        print(f"Warning: Failed to load .env file: {e}")
        return False


# Auto-load .env file for development convenience
if load_dotenv_if_exists():
    print("Configuration loaded from .env file")


# Validate environment on import for early error detection
if not validate_environment():
    print("Warning: Environment validation failed - some features may not work")