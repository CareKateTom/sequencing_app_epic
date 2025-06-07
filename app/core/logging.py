"""
Structured logging configuration for Epic FHIR Integration application.

This module provides a comprehensive logging system with:
- Structured JSON logging for production
- Human-readable format for development
- Context-aware logging with request tracking
- Security-conscious log filtering
- Performance monitoring integration
"""

import os
import sys
import json
import time
import logging
import logging.config
from typing import Dict, Any, Optional, Union
from datetime import datetime
from contextlib import contextmanager
from flask import Flask, request, g, has_request_context
import uuid


class SecurityFilter(logging.Filter):
    """
    Filter sensitive information from log records.
    
    Prevents accidental logging of sensitive data like tokens, passwords,
    and personally identifiable information.
    """
    
    SENSITIVE_KEYS = {
        'password', 'token', 'access_token', 'refresh_token', 'client_secret',
        'authorization', 'secret', 'key', 'ssn', 'social_security_number',
        'date_of_birth', 'dob', 'phone', 'email', 'address'
    }
    
    SENSITIVE_PATTERNS = [
        'Bearer ',  # OAuth tokens
        'Basic ',   # Basic auth
        '***',      # Already masked
    ]
    
    def filter(self, record: logging.LogRecord) -> bool:
        """Filter sensitive data from log record."""
        try:
            # Filter message
            if hasattr(record, 'msg') and record.msg:
                record.msg = self._sanitize_value(str(record.msg))
            
            # Filter args
            if hasattr(record, 'args') and record.args:
                record.args = tuple(
                    self._sanitize_value(str(arg)) if not isinstance(arg, dict) 
                    else self._sanitize_dict(arg) 
                    for arg in record.args
                )
            
            # Filter extra fields
            for key, value in list(record.__dict__.items()):
                if key.lower() in self.SENSITIVE_KEYS:
                    setattr(record, key, self._mask_value(value))
                elif isinstance(value, dict):
                    setattr(record, key, self._sanitize_dict(value))
                elif isinstance(value, str):
                    setattr(record, key, self._sanitize_value(value))
            
            return True
            
        except Exception:
            # If filtering fails, allow the log but indicate filtering error
            record.msg = f"[LOG_FILTER_ERROR] {getattr(record, 'msg', 'Unknown message')}"
            return True
    
    def _sanitize_dict(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Recursively sanitize dictionary values."""
        if not isinstance(data, dict):
            return data
        
        sanitized = {}
        for key, value in data.items():
            if key.lower() in self.SENSITIVE_KEYS:
                sanitized[key] = self._mask_value(value)
            elif isinstance(value, dict):
                sanitized[key] = self._sanitize_dict(value)
            elif isinstance(value, str):
                sanitized[key] = self._sanitize_value(value)
            else:
                sanitized[key] = value
        
        return sanitized
    
    def _sanitize_value(self, value: str) -> str:
        """Sanitize string values containing sensitive patterns."""
        if not isinstance(value, str):
            return value
        
        for pattern in self.SENSITIVE_PATTERNS:
            if pattern in value:
                # Find and mask the sensitive part
                start = value.find(pattern)
                if start != -1:
                    end = start + len(pattern) + 10  # Mask next 10 chars
                    masked = value[:start + len(pattern)] + '***' + value[min(end, len(value)):]
                    value = masked
        
        return value
    
    def _mask_value(self, value: Any) -> str:
        """Mask sensitive values."""
        if value is None:
            return None
        
        str_value = str(value)
        if len(str_value) <= 4:
            return '***'
        elif len(str_value) <= 8:
            return str_value[:2] + '***'
        else:
            return str_value[:3] + '***' + str_value[-2:]


class JSONFormatter(logging.Formatter):
    """
    JSON log formatter for structured logging.
    
    Outputs logs in JSON format suitable for log aggregation systems
    like Google Cloud Logging, ELK stack, etc.
    """
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        log_entry = {
            'timestamp': datetime.utcfromtimestamp(record.created).isoformat() + 'Z',
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
        }
        
        # Add exception info if present
        if record.exc_info:
            log_entry['exception'] = self.formatException(record.exc_info)
        
        # Add request context if available
        if has_request_context():
            log_entry.update(self._get_request_context())
        
        # Add any extra fields
        for key, value in record.__dict__.items():
            if key not in ('name', 'msg', 'args', 'levelname', 'levelno', 'pathname',
                          'filename', 'module', 'exc_info', 'exc_text', 'stack_info',
                          'lineno', 'funcName', 'created', 'msecs', 'relativeCreated',
                          'thread', 'threadName', 'processName', 'process', 'message'):
                log_entry[key] = value
        
        return json.dumps(log_entry, default=str, ensure_ascii=False)
    
    def _get_request_context(self) -> Dict[str, Any]:
        """Extract relevant request context for logging."""
        context = {}
        
        try:
            if request:
                context.update({
                    'request_id': getattr(g, 'request_id', None),
                    'method': request.method,
                    'path': request.path,
                    'remote_addr': request.remote_addr,
                    'user_agent': request.headers.get('User-Agent'),
                })
                
                # Add Epic-specific context if available
                if hasattr(g, 'epic_user_id'):
                    context['epic_user_id'] = g.epic_user_id
                
                if hasattr(g, 'patient_id'):
                    context['patient_id'] = g.patient_id
        
        except Exception:
            # If we can't get request context, don't fail the logging
            pass
        
        return context


class HumanReadableFormatter(logging.Formatter):
    """
    Human-readable formatter for development and console output.
    
    Provides colored output and clean formatting for better readability
    during development.
    """
    
    # ANSI color codes
    COLORS = {
        'DEBUG': '\033[36m',    # Cyan
        'INFO': '\033[32m',     # Green
        'WARNING': '\033[33m',  # Yellow
        'ERROR': '\033[31m',    # Red
        'CRITICAL': '\033[35m', # Magenta
        'RESET': '\033[0m'      # Reset
    }
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record in human-readable format."""
        # Get color for log level
        color = self.COLORS.get(record.levelname, '')
        reset = self.COLORS['RESET']
        
        # Format timestamp
        timestamp = datetime.fromtimestamp(record.created).strftime('%Y-%m-%d %H:%M:%S')
        
        # Build the log line
        log_parts = [
            f"{color}{timestamp}{reset}",
            f"{color}[{record.levelname}]{reset}",
            f"{record.name}",
            f"{record.getMessage()}"
        ]
        
        # Add request ID if available
        if has_request_context() and hasattr(g, 'request_id'):
            log_parts.insert(-1, f"[{g.request_id[:8]}]")
        
        log_line = " ".join(log_parts)
        
        # Add exception info if present
        if record.exc_info:
            log_line += "\n" + self.formatException(record.exc_info)
        
        return log_line


class RequestIDMiddleware:
    """
    Middleware to generate and track request IDs for correlation.
    """
    
    def __init__(self, app: Flask):
        self.app = app
        app.before_request(self._before_request)
        app.after_request(self._after_request)
    
    def _before_request(self):
        """Generate request ID at start of request."""
        g.request_id = str(uuid.uuid4())
        g.request_start_time = time.time()
    
    def _after_request(self, response):
        """Log request completion and add request ID to headers."""
        if hasattr(g, 'request_id'):
            response.headers['X-Request-ID'] = g.request_id
            
            # Log request completion
            if hasattr(g, 'request_start_time'):
                duration = time.time() - g.request_start_time
                logger = logging.getLogger('epic_fhir.request')
                logger.info(
                    f"Request completed",
                    extra={
                        'request_id': g.request_id,
                        'method': request.method,
                        'path': request.path,
                        'status_code': response.status_code,
                        'duration_ms': round(duration * 1000, 2)
                    }
                )
        
        return response


def setup_logging(app: Flask) -> None:
    """
    Configure application logging based on environment.
    
    Args:
        app: Flask application instance
    """
    log_level = app.config.get('LOG_LEVEL', 'INFO').upper()
    is_development = app.config.get('FLASK_ENV') == 'development'
    
    # Configure root logger
    logging.root.setLevel(getattr(logging, log_level))
    
    # Remove default handlers
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)
    
    # Create console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(getattr(logging, log_level))
    
    # Choose formatter based on environment
    if is_development:
        formatter = HumanReadableFormatter()
    else:
        formatter = JSONFormatter()
    
    console_handler.setFormatter(formatter)
    
    # Add security filter
    security_filter = SecurityFilter()
    console_handler.addFilter(security_filter)
    
    # Add handler to root logger
    logging.root.addHandler(console_handler)
    
    # Configure specific loggers
    configure_logger_levels(is_development)
    
    # Set up request tracking
    RequestIDMiddleware(app)
    
    # Log startup
    logger = logging.getLogger('epic_fhir.startup')
    logger.info(
        f"Logging configured",
        extra={
            'level': log_level,
            'environment': app.config.get('FLASK_ENV', 'unknown'),
            'formatter': 'human' if is_development else 'json'
        }
    )


def configure_logger_levels(is_development: bool = False) -> None:
    """Configure log levels for different components."""
    # Application loggers
    loggers_config = {
        'epic_fhir': 'DEBUG' if is_development else 'INFO',
        'epic_fhir.auth': 'DEBUG' if is_development else 'INFO',
        'epic_fhir.fhir': 'DEBUG' if is_development else 'INFO',
        'epic_fhir.hl7': 'DEBUG' if is_development else 'INFO',
        'epic_fhir.request': 'INFO',
        
        # Third-party loggers
        'requests': 'WARNING',
        'urllib3': 'WARNING',
        'google.cloud': 'WARNING',
        'oauthlib': 'WARNING',
        'requests_oauthlib': 'WARNING',
        'werkzeug': 'WARNING' if not is_development else 'INFO',
    }
    
    for logger_name, level in loggers_config.items():
        logger = logging.getLogger(logger_name)
        logger.setLevel(getattr(logging, level))


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance with the epic_fhir prefix.
    
    Args:
        name: Logger name (usually __name__)
        
    Returns:
        Configured logger instance
    """
    # Add epic_fhir prefix if not already present
    if not name.startswith('epic_fhir'):
        if name == '__main__':
            name = 'epic_fhir.main'
        else:
            name = f'epic_fhir.{name}'
    
    return logging.getLogger(name)


@contextmanager
def log_performance(operation: str, logger: Optional[logging.Logger] = None):
    """
    Context manager for logging operation performance.
    
    Args:
        operation: Description of the operation being timed
        logger: Logger to use (defaults to performance logger)
    """
    if logger is None:
        logger = logging.getLogger('epic_fhir.performance')
    
    start_time = time.time()
    exception_occurred = False
    
    try:
        logger.debug(f"Starting operation: {operation}")
        yield
    except Exception as e:
        exception_occurred = True
        duration = time.time() - start_time
        logger.warning(
            f"Operation failed: {operation}",
            extra={
                'operation': operation,
                'duration_ms': round(duration * 1000, 2),
                'error': str(e)
            }
        )
        raise
    finally:
        if not exception_occurred:
            duration = time.time() - start_time
            logger.info(
                f"Operation completed: {operation}",
                extra={
                    'operation': operation,
                    'duration_ms': round(duration * 1000, 2)
                }
            )


def log_epic_event(event_type: str, details: Dict[str, Any], logger: Optional[logging.Logger] = None):
    """
    Log Epic-specific events with structured data.
    
    Args:
        event_type: Type of Epic event (e.g., 'token_refresh', 'fhir_request', 'hl7_message')
        details: Event details dictionary
        logger: Logger to use (defaults to epic logger)
    """
    if logger is None:
        logger = logging.getLogger('epic_fhir.epic_events')
    
    logger.info(
        f"Epic event: {event_type}",
        extra={
            'event_type': event_type,
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            **details
        }
    )


def log_security_event(event_type: str, details: Dict[str, Any], level: str = 'WARNING'):
    """
    Log security-related events for monitoring and alerting.
    
    Args:
        event_type: Type of security event
        details: Event details
        level: Log level for the event
    """
    logger = logging.getLogger('epic_fhir.security')
    
    log_func = getattr(logger, level.lower())
    log_func(
        f"Security event: {event_type}",
        extra={
            'event_type': event_type,
            'security_event': True,
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            **details
        }
    )


def create_audit_log(action: str, resource: str, user_id: Optional[str] = None, details: Optional[Dict[str, Any]] = None):
    """
    Create audit log entries for compliance and security monitoring.
    
    Args:
        action: Action performed (e.g., 'read', 'create', 'update', 'delete')
        resource: Resource affected (e.g., 'patient', 'observation')
        user_id: User performing the action
        details: Additional details about the action
    """
    logger = logging.getLogger('epic_fhir.audit')
    
    audit_entry = {
        'audit_event': True,
        'action': action,
        'resource': resource,
        'timestamp': datetime.utcnow().isoformat() + 'Z',
    }
    
    if user_id:
        audit_entry['user_id'] = user_id
    
    if details:
        audit_entry.update(details)
    
    # Add request context if available
    if has_request_context():
        if hasattr(g, 'request_id'):
            audit_entry['request_id'] = g.request_id
        if hasattr(g, 'epic_user_id'):
            audit_entry['epic_user_id'] = g.epic_user_id
    
    logger.info(f"Audit: {action} {resource}", extra=audit_entry)


# Module-level logger for this file
logger = get_logger(__name__)