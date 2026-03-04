"""
Logging Utilities

Custom log formatters and handlers for production logging.
Includes recursive sensitive data masking for compliance (GDPR, SOC 2).
"""

import json
import logging
import re
from datetime import datetime


class JsonFormatter(logging.Formatter):
    """
    Custom JSON formatter for structured logging.
    Outputs logs in JSON format for easy parsing by log aggregators
    (ELK stack, CloudWatch, Datadog, etc.).
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

        # Add extra context fields
        extra_fields = (
            'request_id', 'user_id', 'ip', 'path',
            'method', 'status_code', 'duration_ms',
        )
        for field in extra_fields:
            if hasattr(record, field):
                log_data[field] = getattr(record, field)

        return json.dumps(log_data)


class SensitiveDataFilter(logging.Filter):
    """
    Filters out sensitive data from log records.

    Scans both the log message string AND all extra attributes recursively,
    masking values whose keys match known sensitive field names. This prevents
    accidental leakage of passwords, tokens, API keys, and PII into log
    aggregators and files.

    Handles:
      - Top-level log message strings (regex-based masking)
      - Extra kwargs passed to logger calls (attribute-level masking)
      - Nested dictionaries (recursive traversal)
      - Lists containing dictionaries (recursive traversal)
    """

    # Sensitive field name patterns (matched case-insensitively as substrings)
    SENSITIVE_FIELDS = frozenset({
        'password',
        'token',
        'secret',
        'api_key',
        'authorization',
        'credit_card',
        'cvv',
        'ssn',
        'refresh',
        'access_token',
        'refresh_token',
        'new_password',
        'old_password',
        'password_confirm',
        'session_key',
    })

    # Pre-compiled regex patterns for message-level masking
    _MESSAGE_PATTERNS = [
        re.compile(
            r'({field}\s*[=:]\s*)[^\s,\}}"\']+'.format(field=field),
            re.IGNORECASE,
        )
        for field in SENSITIVE_FIELDS
    ] + [
        re.compile(
            r'("{field}"\s*:\s*")[^"]+(")'
            .format(field=field),
            re.IGNORECASE,
        )
        for field in SENSITIVE_FIELDS
    ]

    # Attributes that are part of the standard LogRecord and should not be scanned
    _SKIP_ATTRS = frozenset({
        'name', 'msg', 'args', 'created', 'relativeCreated', 'thread',
        'threadName', 'msecs', 'filename', 'funcName', 'levelname', 'levelno',
        'lineno', 'module', 'exc_info', 'exc_text', 'stack_info', 'pathname',
        'process', 'processName', 'taskName',
    })

    _REDACTED = '***REDACTED***'

    def filter(self, record):
        """Filter and mask sensitive data in the log record."""
        # 1. Mask sensitive patterns in the message string
        if hasattr(record, 'msg') and isinstance(record.msg, str):
            record.msg = self._mask_message(record.msg)

        # 2. Mask sensitive values in extra attributes
        for attr_name in list(vars(record)):
            if attr_name.startswith('_') or attr_name in self._SKIP_ATTRS:
                continue

            value = getattr(record, attr_name, None)

            if self._is_sensitive_key(attr_name):
                setattr(record, attr_name, self._REDACTED)
            elif isinstance(value, dict):
                setattr(record, attr_name, self._mask_dict(value))
            elif isinstance(value, (list, tuple)):
                setattr(record, attr_name, self._mask_sequence(value))

        # Always return True — we mask data but never suppress log records
        return True

    def _is_sensitive_key(self, key):
        """Check if a key name contains a sensitive field pattern."""
        key_lower = key.lower()
        return any(field in key_lower for field in self.SENSITIVE_FIELDS)

    def _mask_message(self, message):
        """Replace sensitive data patterns in a log message string."""
        for pattern in self._MESSAGE_PATTERNS:
            message = pattern.sub(
                lambda m: m.group(1) + self._REDACTED + (m.group(2) if m.lastindex and m.lastindex >= 2 else ''),
                message,
            )
        return message

    def _mask_dict(self, data):
        """Recursively mask sensitive values in a dictionary."""
        if not isinstance(data, dict):
            return data

        masked = {}
        for key, value in data.items():
            if self._is_sensitive_key(str(key)):
                masked[key] = self._REDACTED
            elif isinstance(value, dict):
                masked[key] = self._mask_dict(value)
            elif isinstance(value, (list, tuple)):
                masked[key] = self._mask_sequence(value)
            else:
                masked[key] = value
        return masked

    def _mask_sequence(self, seq):
        """Recursively mask sensitive values in a list or tuple."""
        result = []
        for item in seq:
            if isinstance(item, dict):
                result.append(self._mask_dict(item))
            elif isinstance(item, (list, tuple)):
                result.append(self._mask_sequence(item))
            else:
                result.append(item)
        return type(seq)(result) if isinstance(seq, tuple) else result
