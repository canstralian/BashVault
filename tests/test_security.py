
#!/usr/bin/env python3
"""
Security tests for InfoGather
"""

import pytest
import json
from unittest.mock import patch, MagicMock
from security import SecurityManager, validate_json_input, require_auth
from flask import Flask, request, session

class TestSecurityManager:
    """Test security manager functionality"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.security_manager = SecurityManager()
    
    def test_validate_input_general(self):
        """Test general input validation"""
        # Valid input
        assert self.security_manager.validate_input("valid_input") == True
        
        # Invalid inputs
        assert self.security_manager.validate_input("") == False
        assert self.security_manager.validate_input("a" * 1001) == False
        assert self.security_manager.validate_input("<script>alert('xss')</script>") == False
        assert self.security_manager.validate_input("javascript:alert(1)") == False
        assert self.security_manager.validate_input("eval(malicious_code)") == False
    
    def test_validate_target(self):
        """Test target validation"""
        # Valid targets
        assert self.security_manager.validate_input("8.8.8.8", "target") == True
        assert self.security_manager.validate_input("example.com", "target") == True
        assert self.security_manager.validate_input("sub.example.com", "target") == True
        
        # Invalid targets
        assert self.security_manager.validate_input("127.0.0.1", "target") == False
        assert self.security_manager.validate_input("192.168.1.1", "target") == False
        assert self.security_manager.validate_input("invalid..domain", "target") == False
        assert self.security_manager.validate_input("", "target") == False
    
    def test_validate_ports(self):
        """Test port validation"""
        # Valid ports
        assert self.security_manager.validate_input("80", "ports") == True
        assert self.security_manager.validate_input("1-1000", "ports") == True
        assert self.security_manager.validate_input("80,443,8080", "ports") == True
        
        # Invalid ports
        assert self.security_manager.validate_input("", "ports") == False
        assert self.security_manager.validate_input("0", "ports") == False
        assert self.security_manager.validate_input("65536", "ports") == False
        assert self.security_manager.validate_input("invalid", "ports") == False
    
    def test_validate_username(self):
        """Test username validation"""
        # Valid usernames
        assert self.security_manager.validate_input("admin", "username") == True
        assert self.security_manager.validate_input("user123", "username") == True
        assert self.security_manager.validate_input("test_user", "username") == True
        
        # Invalid usernames
        assert self.security_manager.validate_input("", "username") == False
        assert self.security_manager.validate_input("ab", "username") == False
        assert self.security_manager.validate_input("user@domain", "username") == False
        assert self.security_manager.validate_input("user with spaces", "username") == False
    
    def test_validate_email(self):
        """Test email validation"""
        # Valid emails
        assert self.security_manager.validate_input("user@example.com", "email") == True
        assert self.security_manager.validate_input("test.user@domain.org", "email") == True
        
        # Invalid emails
        assert self.security_manager.validate_input("", "email") == False
        assert self.security_manager.validate_input("invalid-email", "email") == False
        assert self.security_manager.validate_input("user@", "email") == False
        assert self.security_manager.validate_input("@domain.com", "email") == False
    
    def test_rate_limiting(self):
        """Test rate limiting functionality"""
        identifier = "test_user"
        
        # Within limit
        for i in range(5):
            assert self.security_manager.check_rate_limit(identifier, limit=10) == True
        
        # Exceed limit
        for i in range(6):
            self.security_manager.check_rate_limit(identifier, limit=10)
        
        assert self.security_manager.check_rate_limit(identifier, limit=10) == False
    
    def test_failed_attempts_tracking(self):
        """Test failed attempts tracking"""
        identifier = "test_user"
        
        # Mock request object
        with patch('security.request') as mock_request:
            mock_request.remote_addr = "192.168.1.100"
            
            # Log failed attempts
            for i in range(3):
                self.security_manager.log_failed_attempt(identifier)
            
            assert len(self.security_manager.failed_attempts[identifier]) == 3
            assert self.security_manager.is_blocked("192.168.1.100") == False
            
            # Block after 5 attempts
            for i in range(2):
                self.security_manager.log_failed_attempt(identifier)
            
            assert self.security_manager.is_blocked("192.168.1.100") == True

class TestSecurityDecorators:
    """Test security decorators"""
    
    def test_require_auth_decorator(self):
        """Test authentication decorator"""
        app = Flask(__name__)
        
        @app.route('/protected')
        @require_auth
        def protected_route():
            return "Success"
        
        with app.test_client() as client:
            # Test without authentication
            response = client.get('/protected')
            assert response.status_code == 401
            
            # Test with authentication
            with client.session_transaction() as sess:
                sess['user_id'] = 1
                sess['last_activity'] = "2024-01-01T00:00:00"
            
            response = client.get('/protected')
            assert response.status_code == 200
    
    def test_validate_json_input_decorator(self):
        """Test JSON input validation decorator"""
        app = Flask(__name__)
        
        @app.route('/api/test', methods=['POST'])
        @validate_json_input(['target', 'modules'])
        def test_endpoint():
            return jsonify({'success': True})
        
        with app.test_client() as client:
            # Test without JSON
            response = client.post('/api/test')
            assert response.status_code == 400
            
            # Test with missing fields
            response = client.post('/api/test', 
                                 json={'target': 'example.com'})
            assert response.status_code == 400
            
            # Test with valid data
            response = client.post('/api/test', 
                                 json={'target': 'example.com', 'modules': ['test']})
            assert response.status_code == 200

if __name__ == '__main__':
    pytest.main([__file__])
