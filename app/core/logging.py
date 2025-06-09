"""
Healthcare compliance logging for Epic FHIR Integration.

Focused on security events, audit trails, and incident investigation.
Follows principle: "Secure and compliant, not enterprise-ready"
"""

import os
import sys
import json
import logging
import uuid
from typing import Dict, Any, Optional
from datetime import datetime
from flask import Flask, request, g, has_request_context


class SecurityFilter(logging.Filter):
    """Filter sensitive healthcare data from logs."""
    
    SENSITIVE_KEYS = {
        'password', 'token', 'access_token', 'refresh_token', 'secret',
        'ssn', 'date_of_birth', 'dob', 'phone', 'email'
    }
    
    def filter(self, record: logging.LogRecord) -> bool:
        """Remove sensitive data from log records."""
        try:
            # Filter message
            if hasattr(record, 'msg'):
                record.msg = self._sanitize_value(str(record.msg))
            
            # Filter extra fields
            for key, value in list(record.__dict__.items()):
                if key.lower() in self.SENSITIVE_KEYS:
                    setattr(record, key, '***')
                elif isinstance(value, dict):
                    setattr(record, key, self._sanitize_dict(value))
                elif isinstance(value, str) and 'Bearer ' in value:
                    setattr(record, key, 'Bearer ***')
            
            return True
        except Exception:
            # If filtering fails, allow log but mask message
            record.msg = "[FILTER_ERROR] " + str(getattr(record, 'msg', ''))
            return True
    
    def _sanitize_dict(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Remove sensitive keys from dictionaries."""
        if not isinstance(data, dict):
            return data
        
        sanitized = {}
        for key, value in data.items():
            if key.lower() in self.SENSITIVE_KEYS:
                sanitized[key] = '***'
            elif isinstance(value, dict):
                sanitized[key] = self._sanitize_dict(value)
            else:
                sanitized[key] = value
        return sanitized
    
    def _sanitize_value(self, value: str) -> str:
        """Mask Bearer tokens in strings."""
        if 'Bearer ' in value:
            return value.replace(value[value.find('Bearer '):value.find('Bearer ') + 20], 'Bearer ***')
        return value


class ComplianceFormatter(logging.Formatter):
    """JSON formatter for compliance and audit logging."""
    
    def format(self, record: logging.LogRecord) -> str:
        """Format as JSON for log aggregation systems."""
        log_entry = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
        }
        
        # Add exception info
        if record.exc_info:
            log_entry['exception'] = self.formatException(record.exc_info)
        
        # Add request context for audit trails
        if has_request_context():
            try:
                log_entry.update({
                    'request_id': getattr(g, 'request_id', None),
                    'method': request.method,
                    'path': request.path,
                    'remote_addr': request.remote_addr,
                    'epic_user_id': getattr(g, 'epic_user_id', None),
                })
            except:
                pass  # Don't fail logging if request context unavailable
        
        # Add extra fields (security events, audit data)
        for key, value in record.__dict__.items():
            if key not in ('name', 'msg', 'args', 'levelname', 'pathname',
                          'filename', 'module', 'exc_info', 'lineno', 'funcName',
                          'created', 'thread', 'process', 'message'):
                log_entry[key] = value
        
        return json.dumps(log_entry, default=str)


class RequestTracker:
    """Simple request ID tracking for audit correlation."""
    
    def __init__(self, app: Flask):
        app.before_request(self._before_request)
        app.after_request(self._after_request)
    
    def _before_request(self):
        """Generate request ID for audit trail."""
        g.request_id = str(uuid.uuid4())
    
    def _after_request(self, response):
        """Add request ID to response headers."""
        if hasattr(g, 'request_id'):
            response.headers['X-Request-ID'] = g.request_id
        return response


def setup_logging(app: Flask) -> None:
    """Configure healthcare compliance logging."""
    log_level = app.config.get('LOG_LEVEL', 'INFO').upper()
    is_dev = app.config.get('FLASK_ENV') == 'development'
    
    # Clear existing handlers
    logging.root.handlers.clear()
    
    # Create console handler
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(getattr(logging, log_level))
    
    # Use simple format for development, JSON for production
    if is_dev:
        formatter = logging.Formatter(
            '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
        )
    else:
        formatter = ComplianceFormatter()
    
    handler.setFormatter(formatter)
    handler.addFilter(SecurityFilter())
    
    # Configure root logger
    logging.root.setLevel(getattr(logging, log_level))
    logging.root.addHandler(handler)
    
    # Set third-party log levels
    logging.getLogger('requests').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('google.cloud').setLevel(logging.WARNING)
    
    # Setup request tracking
    RequestTracker(app)
    
    logger = logging.getLogger('epic_fhir')
    logger.info(f"Compliance logging configured (level: {log_level})")


def get_logger(name: str) -> logging.Logger:
    """Get logger with epic_fhir prefix."""
    if not name.startswith('epic_fhir'):
        name = f'epic_fhir.{name.split(".")[-1]}'  # Use just the module name
    return logging.getLogger(name)


def log_security_event(event_type: str, details: Dict[str, Any], level: str = 'WARNING'):
    """Log security events for SOC monitoring."""
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


def log_epic_event(event_type: str, details: Dict[str, Any]):
    """Log Epic-specific events for operational monitoring."""
    logger = logging.getLogger('epic_fhir.epic')
    logger.info(
        f"Epic event: {event_type}",
        extra={
            'event_type': event_type,
            'epic_event': True,
            **details
        }
    )


def create_audit_log(action: str, resource: str, user_id: Optional[str] = None, 
                    details: Optional[Dict[str, Any]] = None):
    """Create audit log for HIPAA compliance."""
    logger = logging.getLogger('epic_fhir.audit')
    
    audit_entry = {
        'audit_event': True,
        'action': action,
        'resource': resource,
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'user_id': user_id,
    }
    
    if details:
        audit_entry.update(details)
    
    # Add request context
    if has_request_context() and hasattr(g, 'request_id'):
        audit_entry['request_id'] = g.request_id
    
    logger.info(f"Audit: {action} {resource}", extra=audit_entry)