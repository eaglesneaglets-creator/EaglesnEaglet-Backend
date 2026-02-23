"""
Logging Utilities

Custom log formatters and handlers for production logging.
"""

import json
import logging
from datetime import datetime


class JsonFormatter(logging.Formatter):
    """
    Custom JSON formatter for structured logging.
    Outputs logs in JSON format for easy parsing by log aggregators.
    """

    def format(self, record):
        log_data = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
        }

        # Add exception info if present
        if record.exc_info:
            log_data['exception'] = self.formatException(record.exc_info)

        # Add extra fields
        if hasattr(record, 'request_id'):
            log_data['request_id'] = record.request_id
        if hasattr(record, 'user_id'):
            log_data['user_id'] = record.user_id
        if hasattr(record, 'ip'):
            log_data['ip'] = record.ip
        if hasattr(record, 'path'):
            log_data['path'] = record.path
        if hasattr(record, 'method'):
            log_data['method'] = record.method
        if hasattr(record, 'status_code'):
            log_data['status_code'] = record.status_code
        if hasattr(record, 'duration_ms'):
            log_data['duration_ms'] = record.duration_ms

        return json.dumps(log_data)


class SensitiveDataFilter(logging.Filter):
    """
    Filters out sensitive data from logs.
    Masks passwords, tokens, and other sensitive information.
    """

    SENSITIVE_FIELDS = [
        'password',
        'token',
        'secret',
        'api_key',
        'authorization',
        'credit_card',
        'cvv',
        'ssn',
    ]

    def filter(self, record):
        if hasattr(record, 'msg') and isinstance(record.msg, str):
            for field in self.SENSITIVE_FIELDS:
                # Mask sensitive data in log messages
                if field in record.msg.lower():
                    record.msg = self._mask_sensitive(record.msg, field)
        return True

    def _mask_sensitive(self, message, field):
        """Replace sensitive data with masked version."""
        import re
        # Pattern to match field=value or "field": "value"
        patterns = [
            rf'({field}\s*[=:]\s*)[^\s,\}}"\']+',
            rf'("{field}"\s*:\s*")[^"]+(")',
        ]
        for pattern in patterns:
            message = re.sub(pattern, r'\1***REDACTED***\2', message, flags=re.IGNORECASE)
        return message
