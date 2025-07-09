
import re
import secrets
import hashlib
import hmac
import logging
from datetime import datetime, timedelta
from functools import wraps
from typing import Optional, Dict, Any
from flask import request, jsonify, session, g
from werkzeug.security import generate_password_hash, check_password_hash
import ipaddress

logger = logging.getLogger(__name__)

class SecurityManager:
    """Centralized security management"""
    
    def __init__(self):
        self.failed_attempts = {}
        self.blocked_ips = set()
        self.rate_limits = {}
    
    def validate_input(self, data: str, input_type: str = 'general') -> bool:
        """Validate and sanitize input data"""
        if not data or len(data) > 1000:
            return False
        
        # Remove null bytes and control characters
        data = data.replace('\x00', '').strip()
        
        if input_type == 'target':
            # Validate IP addresses or domain names
            return self._validate_target(data)
        elif input_type == 'ports':
            return self._validate_ports(data)
        elif input_type == 'username':
            return self._validate_username(data)
        elif input_type == 'email':
            return self._validate_email(data)
        
        # General validation - no dangerous characters
        dangerous_patterns = [
            r'<script[^>]*>.*?</script>',
            r'javascript:',
            r'on\w+\s*=',
            r'eval\s*\(',
            r'exec\s*\(',
            r'system\s*\(',
            r'os\.system',
            r'subprocess\.',
            r'__import__',
            r'\.\./',
            r'\.\.\\',
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, data, re.IGNORECASE):
                logger.warning(f"Dangerous pattern detected: {pattern}")
                return False
        
        return True
    
    def _validate_target(self, target: str) -> bool:
        """Validate target IP or domain"""
        if not target or len(target) > 255:
            return False
        
        # Check for private/internal networks
        try:
            ip = ipaddress.ip_address(target)
            if ip.is_private or ip.is_loopback or ip.is_multicast:
                logger.warning(f"Attempted scan of private/internal IP: {target}")
                return False
        except ValueError:
            # Not an IP, check if it's a valid domain
            domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
            if not re.match(domain_pattern, target):
                return False
        
        return True
    
    def _validate_ports(self, ports: str) -> bool:
        """Validate port specification"""
        if not ports or len(ports) > 100:
            return False
        
        # Allow ranges like 1-1000 or comma-separated like 80,443,8080
        port_pattern = r'^(\d{1,5}(-\d{1,5})?)(,\d{1,5}(-\d{1,5})?)*$'
        if not re.match(port_pattern, ports):
            return False
        
        # Check individual port numbers
        for part in ports.split(','):
            if '-' in part:
                start, end = part.split('-')
                if not (1 <= int(start) <= 65535 and 1 <= int(end) <= 65535):
                    return False
            else:
                if not (1 <= int(part) <= 65535):
                    return False
        
        return True
    
    def _validate_username(self, username: str) -> bool:
        """Validate username format"""
        if not username or len(username) < 3 or len(username) > 50:
            return False
        
        # Allow alphanumeric, underscore, hyphen
        return re.match(r'^[a-zA-Z0-9_-]+$', username) is not None
    
    def _validate_email(self, email: str) -> bool:
        """Validate email format"""
        if not email or len(email) > 254:
            return False
        
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(email_pattern, email) is not None
    
    def check_rate_limit(self, identifier: str, limit: int = 10, window: int = 60) -> bool:
        """Check if request is within rate limits"""
        now = datetime.utcnow()
        
        if identifier not in self.rate_limits:
            self.rate_limits[identifier] = []
        
        # Remove old entries
        self.rate_limits[identifier] = [
            timestamp for timestamp in self.rate_limits[identifier]
            if now - timestamp < timedelta(seconds=window)
        ]
        
        # Check if within limit
        if len(self.rate_limits[identifier]) >= limit:
            return False
        
        # Add current request
        self.rate_limits[identifier].append(now)
        return True
    
    def log_failed_attempt(self, identifier: str, attempt_type: str = 'login'):
        """Log failed authentication attempt"""
        now = datetime.utcnow()
        
        if identifier not in self.failed_attempts:
            self.failed_attempts[identifier] = []
        
        self.failed_attempts[identifier].append({
            'timestamp': now,
            'type': attempt_type,
            'ip': request.remote_addr
        })
        
        # Block IP after 5 failed attempts in 15 minutes
        recent_attempts = [
            attempt for attempt in self.failed_attempts[identifier]
            if now - attempt['timestamp'] < timedelta(minutes=15)
        ]
        
        if len(recent_attempts) >= 5:
            self.blocked_ips.add(request.remote_addr)
            logger.warning(f"IP blocked due to failed attempts: {request.remote_addr}")
    
    def is_blocked(self, ip: str) -> bool:
        """Check if IP is blocked"""
        return ip in self.blocked_ips
    
    def generate_csrf_token(self) -> str:
        """Generate CSRF token"""
        return secrets.token_hex(32)
    
    def verify_csrf_token(self, token: str) -> bool:
        """Verify CSRF token"""
        return token and session.get('csrf_token') == token

# Global security manager instance
security_manager = SecurityManager()

def require_auth(f):
    """Enhanced authentication decorator"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if IP is blocked
        if security_manager.is_blocked(request.remote_addr):
            return jsonify({'error': 'Access denied'}), 403
        
        # Check authentication
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        
        # Check session timeout
        if 'last_activity' in session:
            last_activity = datetime.fromisoformat(session['last_activity'])
            if datetime.utcnow() - last_activity > timedelta(hours=1):
                session.clear()
                return jsonify({'error': 'Session expired'}), 401
        
        # Update last activity
        session['last_activity'] = datetime.utcnow().isoformat()
        
        return f(*args, **kwargs)
    
    return decorated_function

def validate_json_input(required_fields: list = None):
    """Decorator to validate JSON input"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not request.is_json:
                return jsonify({'error': 'Content-Type must be application/json'}), 400
            
            try:
                data = request.get_json()
                if not data:
                    return jsonify({'error': 'No JSON data provided'}), 400
                
                # Check required fields
                if required_fields:
                    missing_fields = [field for field in required_fields if field not in data]
                    if missing_fields:
                        return jsonify({'error': f'Missing required fields: {missing_fields}'}), 400
                
                # Validate input data
                for key, value in data.items():
                    if isinstance(value, str):
                        if not security_manager.validate_input(value, key):
                            return jsonify({'error': f'Invalid input for field: {key}'}), 400
                
                return f(*args, **kwargs)
            except Exception as e:
                logger.error(f"JSON validation error: {str(e)}")
                return jsonify({'error': 'Invalid JSON data'}), 400
        
        return decorated_function
    return decorator

def add_security_headers(response):
    """Add security headers to response"""
    headers = {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';"
    }
    
    for header, value in headers.items():
        response.headers[header] = value
    
    return response
