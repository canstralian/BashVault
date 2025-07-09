"""
Test suite for InfoGather Web Dashboard
Tests for authentication, scanning, and API endpoints
"""

import pytest
import json
import os
import tempfile
from unittest.mock import patch, MagicMock
from datetime import datetime

# Set test environment variables before importing app
os.environ['FLASK_ENV'] = 'testing'
os.environ['FLASK_SECRET_KEY'] = 'test-secret-key'
os.environ['DATABASE_URL'] = 'sqlite:///:memory:'

from web_dashboard_simple import app, init_database, get_db_connection


@pytest.fixture
def client():
    """Create test client with temporary database"""
    app.config['TESTING'] = True
    app.config['DATABASE_URL'] = 'sqlite:///:memory:'
    
    with app.test_client() as client:
        with app.app_context():
            init_database()
            yield client


@pytest.fixture
def authenticated_client(client):
    """Create authenticated test client"""
    # Register test user
    client.post('/login', data={
        'username': 'testuser',
        'password': 'testpass123',
        'action': 'register'
    })
    
    # Login
    client.post('/login', data={
        'username': 'testuser',
        'password': 'testpass123',
        'action': 'login'
    })
    
    return client


class TestAuthentication:
    """Test authentication and user management"""
    
    def test_login_page_loads(self, client):
        """Test login page loads successfully"""
        response = client.get('/login')
        assert response.status_code == 200
        assert b'Login' in response.data
    
    def test_register_new_user(self, client):
        """Test user registration"""
        response = client.post('/login', data={
            'username': 'newuser',
            'password': 'password123',
            'action': 'register'
        })
        assert response.status_code == 302  # Redirect after successful registration
    
    def test_login_valid_user(self, client):
        """Test login with valid credentials"""
        # Register user first
        client.post('/login', data={
            'username': 'testuser',
            'password': 'testpass123',
            'action': 'register'
        })
        
        # Login
        response = client.post('/login', data={
            'username': 'testuser',
            'password': 'testpass123',
            'action': 'login'
        })
        assert response.status_code == 302  # Redirect after successful login
    
    def test_login_invalid_credentials(self, client):
        """Test login with invalid credentials"""
        response = client.post('/login', data={
            'username': 'nonexistent',
            'password': 'wrongpass',
            'action': 'login'
        })
        assert response.status_code == 200  # Stay on login page
        assert b'Invalid credentials' in response.data
    
    def test_logout(self, authenticated_client):
        """Test user logout"""
        response = authenticated_client.get('/logout')
        assert response.status_code == 302  # Redirect to login


class TestDashboard:
    """Test dashboard functionality"""
    
    def test_dashboard_requires_auth(self, client):
        """Test dashboard redirects to login when not authenticated"""
        response = client.get('/')
        assert response.status_code == 302
        assert '/login' in response.location
    
    def test_dashboard_loads_authenticated(self, authenticated_client):
        """Test dashboard loads for authenticated user"""
        response = authenticated_client.get('/')
        assert response.status_code == 200
        assert b'InfoGather Dashboard' in response.data
    
    def test_scan_page_loads(self, authenticated_client):
        """Test scan configuration page loads"""
        response = authenticated_client.get('/scan')
        assert response.status_code == 200
        assert b'Configure Scan' in response.data


class TestScanAPI:
    """Test scan API endpoints"""
    
    @patch('modules.network_scanner.NetworkScanner')
    def test_start_scan_valid_target(self, mock_scanner, authenticated_client):
        """Test starting scan with valid target"""
        mock_scanner.return_value.scan_network.return_value = {
            'hosts': ['192.168.1.1'],
            'ports': [{'port': 80, 'state': 'open'}]
        }
        
        response = authenticated_client.post('/api/scan/start', json={
            'target': '192.168.1.1',
            'ports': '80,443',
            'modules': ['network_scan']
        })
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['status'] == 'started'
        assert 'scan_id' in data
    
    def test_start_scan_invalid_target(self, authenticated_client):
        """Test starting scan with invalid target"""
        response = authenticated_client.post('/api/scan/start', json={
            'target': 'invalid-target',
            'ports': '80',
            'modules': ['network_scan']
        })
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert data['status'] == 'error'
    
    def test_start_scan_missing_target(self, authenticated_client):
        """Test starting scan without target"""
        response = authenticated_client.post('/api/scan/start', json={
            'ports': '80',
            'modules': ['network_scan']
        })
        
        assert response.status_code == 400
    
    def test_get_scan_status_invalid_id(self, authenticated_client):
        """Test getting status for non-existent scan"""
        response = authenticated_client.get('/api/scan/status/nonexistent')
        assert response.status_code == 404
    
    def test_get_scan_results_invalid_id(self, authenticated_client):
        """Test getting results for non-existent scan"""
        response = authenticated_client.get('/api/scan/results/nonexistent')
        assert response.status_code == 404


class TestHealthEndpoints:
    """Test health check and monitoring endpoints"""
    
    def test_health_check(self, client):
        """Test health check endpoint"""
        response = client.get('/health')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['status'] == 'healthy'
        assert 'timestamp' in data
    
    def test_dashboard_stats(self, authenticated_client):
        """Test dashboard statistics endpoint"""
        response = authenticated_client.get('/api/dashboard/stats')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'total_scans' in data
        assert 'active_scans' in data


class TestErrorHandling:
    """Test error handling and edge cases"""
    
    def test_404_error(self, client):
        """Test 404 error handling"""
        response = client.get('/nonexistent')
        assert response.status_code == 404
    
    def test_invalid_json(self, authenticated_client):
        """Test handling of invalid JSON"""
        response = authenticated_client.post('/api/scan/start', 
                                           data='invalid json',
                                           content_type='application/json')
        assert response.status_code == 400


class TestSecurityFeatures:
    """Test security features and validation"""
    
    def test_sql_injection_protection(self, authenticated_client):
        """Test SQL injection protection"""
        # Attempt SQL injection in username
        response = authenticated_client.post('/login', data={
            'username': "'; DROP TABLE users; --",
            'password': 'password',
            'action': 'login'
        })
        assert response.status_code == 200  # Should not cause error
    
    def test_xss_protection(self, authenticated_client):
        """Test XSS protection"""
        # Attempt XSS in target field
        response = authenticated_client.post('/api/scan/start', json={
            'target': '<script>alert("xss")</script>',
            'ports': '80',
            'modules': ['network_scan']
        })
        assert response.status_code == 400  # Should be rejected
    
    def test_csrf_protection(self, client):
        """Test CSRF protection"""
        # This would need proper CSRF token implementation
        # For now, test that forms require authentication
        response = client.post('/api/scan/start', json={
            'target': '192.168.1.1',
            'ports': '80',
            'modules': ['network_scan']
        })
        assert response.status_code == 302  # Redirect to login


class TestDatabaseOperations:
    """Test database operations and data integrity"""
    
    def test_database_connection(self, client):
        """Test database connection"""
        with app.app_context():
            try:
                with get_db_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute("SELECT 1")
                    result = cursor.fetchone()
                    assert result[0] == 1
            except Exception as e:
                pytest.fail(f"Database connection failed: {e}")
    
    def test_user_creation_and_retrieval(self, client):
        """Test user creation and retrieval"""
        with app.app_context():
            # This would test the user management functions
            # Implementation depends on the specific database schema
            pass


class TestRateLimiting:
    """Test rate limiting and abuse prevention"""
    
    def test_scan_rate_limiting(self, authenticated_client):
        """Test scan rate limiting"""
        # Start multiple scans rapidly
        scan_requests = []
        for i in range(5):
            response = authenticated_client.post('/api/scan/start', json={
                'target': f'192.168.1.{i}',
                'ports': '80',
                'modules': ['network_scan']
            })
            scan_requests.append(response.status_code)
        
        # Should have some rate limiting after multiple requests
        # Implementation depends on rate limiting logic
        assert any(status != 200 for status in scan_requests[-2:])


class TestReportGeneration:
    """Test report generation and export"""
    
    def test_export_report_json(self, authenticated_client):
        """Test JSON report export"""
        # Would need to create a scan first
        # Then test export functionality
        pass
    
    def test_export_report_html(self, authenticated_client):
        """Test HTML report export"""
        # Would need to create a scan first
        # Then test export functionality
        pass


if __name__ == '__main__':
    pytest.main([__file__])