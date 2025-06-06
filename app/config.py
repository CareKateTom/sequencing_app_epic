"""
Configuration management for Epic FHIR Integration application.

This module provides environment-based configuration with validation,
type hints, and proper defaults for all application settings.
"""

import os
from typing import Optional, Union
from pathlib import Path


class ConfigError(Exception):
    """Raised when configuration is invalid or missing required values."""
    pass


class BaseConfig:
    """Base configuration with common settings and validation."""
    
    def __init__(self):
        """Initialize configuration and validate required settings."""
        self._load_environment()
        self._validate_required_settings()
    
    def _load_environment(self):
        """Load configuration from environment variables."""
        # Flask Configuration
        self.SECRET_KEY = self._get_required_env('SECRET_KEY')
        self.FLASK_ENV = os.getenv('FLASK_ENV', 'production')
        self.FLASK_DEBUG = self._get_bool_env('FLASK_DEBUG', False)
        
        # Epic FHIR Configuration
        self.EPIC_BASE_URL = self._get_required_env('EPIC_BASE_URL')
        self.EPIC_CLIENT_ID_SECRET = self._get_required_env('EPIC_CLIENT_ID_SECRET')
        
        # GCP Configuration
        self.GCP_PROJECT_ID = self._get_required_env('GCP_PROJECT_ID')
        
        # Application Settings
        self.LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO').upper()
        self.SESSION_TIMEOUT_HOURS = self._get_int_env('SESSION_TIMEOUT_HOURS', 8)
        
        # SSL Configuration
        self.SSL_CERT_PATH = os.getenv('SSL_CERT_PATH', 'certs/cert.pem')
        self.SSL_KEY_PATH = os.getenv('SSL_KEY_PATH', 'certs/key.pem')
        
        # Development Server Settings
        self.HOST = os.getenv('HOST', 'localhost')
        self.PORT = self._get_int_env('PORT', 443)
        
        # Optional Settings
        self.DATABASE_URL = os.getenv('DATABASE_URL')
        self.REDIS_URL = os.getenv('REDIS_URL')
    
    def _get_required_env(self, key: str) -> str:
        """Get required environment variable or raise ConfigError."""
        value = os.getenv(key)
        if not value:
            raise ConfigError(f"Required environment variable '{key}' is not set")
        return value
    
    def _get_bool_env(self, key: str, default: bool = False) -> bool:
        """Get boolean environment variable with proper conversion."""
        value = os.getenv(key, '').lower()
        if value in ('true', '1', 'yes', 'on'):
            return True
        elif value in ('false', '0', 'no', 'off'):
            return False
        return default
    
    def _get_int_env(self, key: str, default: int) -> int:
        """Get integer environment variable with validation."""
        value = os.getenv(key)
        if value is None:
            return default
        
        try:
            return int(value)
        except ValueError:
            raise ConfigError(f"Environment variable '{key}' must be an integer, got: {value}")
    
    def _validate_required_settings(self):
        """Validate that all required settings are properly configured."""
        # Validate Epic base URL format
        if not self.EPIC_BASE_URL.startswith(('http://', 'https://')):
            raise ConfigError(f"EPIC_BASE_URL must start with http:// or https://, got: {self.EPIC_BASE_URL}")
        
        # Validate log level
        valid_log_levels = {'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'}
        if self.LOG_LEVEL not in valid_log_levels:
            raise ConfigError(f"LOG_LEVEL must be one of {valid_log_levels}, got: {self.LOG_LEVEL}")
        
        # Validate session timeout
        if self.SESSION_TIMEOUT_HOURS <= 0:
            raise ConfigError("SESSION_TIMEOUT_HOURS must be greater than 0")
        
        # Validate port range
        if not (1 <= self.PORT <= 65535):
            raise ConfigError(f"PORT must be between 1 and 65535, got: {self.PORT}")
    
    def validate_ssl_files(self) -> bool:
        """Check if SSL certificate files exist."""
        cert_path = Path(self.SSL_CERT_PATH)
        key_path = Path(self.SSL_KEY_PATH)
        
        if not cert_path.exists():
            print(f"Warning: SSL certificate file not found: {cert_path}")
            return False
        
        if not key_path.exists():
            print(f"Warning: SSL key file not found: {key_path}")
            return False
        
        return True
    
    def get_ssl_context(self) -> Optional[tuple]:
        """Get SSL context for Flask if certificate files exist."""
        if self.validate_ssl_files():
            return (self.SSL_CERT_PATH, self.SSL_KEY_PATH)
        return None
    
    @property
    def is_development(self) -> bool:
        """Check if running in development mode."""
        return self.FLASK_ENV.lower() == 'development'
    
    @property
    def is_production(self) -> bool:
        """Check if running in production mode."""
        return self.FLASK_ENV.lower() == 'production'
    
    @property
    def session_timeout_seconds(self) -> int:
        """Get session timeout in seconds."""
        return self.SESSION_TIMEOUT_HOURS * 3600
    
    def __repr__(self) -> str:
        """Safe representation of config (excludes sensitive data)."""
        safe_attrs = [
            'FLASK_ENV', 'EPIC_BASE_URL', 'GCP_PROJECT_ID', 
            'LOG_LEVEL', 'HOST', 'PORT', 'SESSION_TIMEOUT_HOURS'
        ]
        attrs = [f"{attr}={getattr(self, attr)!r}" for attr in safe_attrs]
        return f"<Config({', '.join(attrs)})>"


class DevelopmentConfig(BaseConfig):
    """Development-specific configuration."""
    
    def __init__(self):
        super().__init__()
        
        # Override for development
        self.FLASK_DEBUG = True
        
        # Development-specific settings
        self.TESTING = False
        self.WTF_CSRF_ENABLED = False  # Disable CSRF for development
        
        # More verbose logging in development
        if self.LOG_LEVEL == 'INFO':
            self.LOG_LEVEL = 'DEBUG'


class ProductionConfig(BaseConfig):
    """Production-specific configuration with enhanced security."""
    
    def __init__(self):
        super().__init__()
        
        # Production security settings
        self.FLASK_DEBUG = False
        self.TESTING = False
        self.WTF_CSRF_ENABLED = True
        
        # Require SSL files in production
        if not self.validate_ssl_files():
            raise ConfigError("SSL certificate files are required in production")
        
        # Ensure production has secure secret key
        if len(self.SECRET_KEY) < 32:
            raise ConfigError("SECRET_KEY must be at least 32 characters in production")


class TestingConfig(BaseConfig):
    """Testing-specific configuration."""
    
    def __init__(self):
        # Override some environment variables for testing
        os.environ.setdefault('SECRET_KEY', 'test-secret-key-32-characters-long')
        os.environ.setdefault('EPIC_BASE_URL', 'https://test.epic.com/api/FHIR/R4')
        os.environ.setdefault('EPIC_CLIENT_ID_SECRET', 'test_client_id')
        os.environ.setdefault('GCP_PROJECT_ID', 'test-project-123')
        
        super().__init__()
        
        # Testing-specific settings
        self.TESTING = True
        self.FLASK_DEBUG = True
        self.WTF_CSRF_ENABLED = False
        
        # Use in-memory database for testing
        self.DATABASE_URL = 'sqlite:///:memory:'
        
        # Shorter session timeout for testing
        self.SESSION_TIMEOUT_HOURS = 1


def load_config() -> Union[DevelopmentConfig, ProductionConfig, TestingConfig]:
    """
    Factory function to load the appropriate configuration based on environment.
    
    Returns:
        Configured instance based on FLASK_ENV environment variable
        
    Raises:
        ConfigError: If configuration is invalid or environment is unknown
    """
    env = os.getenv('FLASK_ENV', 'production').lower()
    
    if env == 'development':
        return DevelopmentConfig()
    elif env == 'production':
        return ProductionConfig()
    elif env == 'testing':
        return TestingConfig()
    else:
        raise ConfigError(f"Unknown FLASK_ENV: {env}. Must be 'development', 'production', or 'testing'")


def load_dotenv_file(dotenv_path: Optional[str] = None) -> bool:
    """
    Load environment variables from .env file.
    
    Args:
        dotenv_path: Path to .env file. If None, looks for .env in current directory
        
    Returns:
        True if .env file was found and loaded, False otherwise
    """
    if dotenv_path is None:
        dotenv_path = '.env'
    
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
                
                # Parse KEY=VALUE format
                if '=' in line:
                    key, value = line.split('=', 1)
                    key = key.strip()
                    value = value.strip()
                    
                    # Remove quotes if present
                    if value.startswith('"') and value.endswith('"'):
                        value = value[1:-1]
                    elif value.startswith("'") and value.endswith("'"):
                        value = value[1:-1]
                    
                    # Only set if not already in environment
                    if key not in os.environ:
                        os.environ[key] = value
        
        return True
        
    except Exception as e:
        print(f"Warning: Failed to load .env file: {e}")
        return False


# Auto-load .env file when module is imported
if load_dotenv_file():
    print("Loaded configuration from .env file")