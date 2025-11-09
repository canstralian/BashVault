#!/usr/bin/env python3
"""
Tests for Marshmallow validation schemas
"""

import pytest
from schemas import (
    ScanRequestSchema, 
    LoginSchema, 
    ScanFilterSchema,
    validate_request_data
)
from marshmallow import ValidationError


class TestScanRequestSchema:
    """Tests for ScanRequestSchema"""
    
    def test_valid_scan_request_with_domain(self):
        """Test valid scan request with domain target"""
        data = {
            'target': 'example.com',
            'ports': '80,443',
            'modules': ['network_scan', 'dns_enum']
        }
        validated, errors = validate_request_data(ScanRequestSchema, data)
        assert errors is None
        assert validated['target'] == 'example.com'
        assert validated['ports'] == '80,443'
        assert len(validated['modules']) == 2
    
    def test_valid_scan_request_with_ip(self):
        """Test valid scan request with IP target"""
        data = {
            'target': '192.168.1.1',
            'ports': '1-1000',
            'modules': ['network_scan']
        }
        validated, errors = validate_request_data(ScanRequestSchema, data)
        assert errors is None
        assert validated['target'] == '192.168.1.1'
    
    def test_valid_scan_request_with_cidr(self):
        """Test valid scan request with CIDR target"""
        data = {
            'target': '192.168.1.0/24',
            'ports': '80',
            'modules': ['network_scan']
        }
        validated, errors = validate_request_data(ScanRequestSchema, data)
        assert errors is None
        assert validated['target'] == '192.168.1.0/24'
    
    def test_default_ports(self):
        """Test default port specification"""
        data = {
            'target': 'example.com',
            'modules': ['network_scan']
        }
        validated, errors = validate_request_data(ScanRequestSchema, data)
        assert errors is None
        assert validated['ports'] == '1-1000'
    
    def test_missing_target(self):
        """Test validation fails without target"""
        data = {
            'ports': '80',
            'modules': ['network_scan']
        }
        validated, errors = validate_request_data(ScanRequestSchema, data)
        assert errors is not None
        assert 'target' in errors
    
    def test_missing_modules(self):
        """Test validation fails without modules"""
        data = {
            'target': 'example.com',
            'ports': '80'
        }
        validated, errors = validate_request_data(ScanRequestSchema, data)
        assert errors is not None
        assert 'modules' in errors
    
    def test_empty_modules(self):
        """Test validation fails with empty modules list"""
        data = {
            'target': 'example.com',
            'ports': '80',
            'modules': []
        }
        validated, errors = validate_request_data(ScanRequestSchema, data)
        assert errors is not None
        assert 'modules' in errors
    
    def test_invalid_module_name(self):
        """Test validation fails with invalid module"""
        data = {
            'target': 'example.com',
            'ports': '80',
            'modules': ['invalid_module']
        }
        validated, errors = validate_request_data(ScanRequestSchema, data)
        assert errors is not None
        assert 'modules' in errors
    
    def test_invalid_target_format(self):
        """Test validation fails with invalid target format"""
        data = {
            'target': 'not a valid target!@#',
            'ports': '80',
            'modules': ['network_scan']
        }
        validated, errors = validate_request_data(ScanRequestSchema, data)
        assert errors is not None
        assert 'target' in errors
    
    def test_invalid_ip_octets(self):
        """Test validation fails with invalid IP octets"""
        data = {
            'target': '192.168.1.999',
            'ports': '80',
            'modules': ['network_scan']
        }
        validated, errors = validate_request_data(ScanRequestSchema, data)
        assert errors is not None
        assert 'target' in errors
    
    def test_invalid_port_format(self):
        """Test validation fails with invalid port format"""
        data = {
            'target': 'example.com',
            'ports': 'abc',
            'modules': ['network_scan']
        }
        validated, errors = validate_request_data(ScanRequestSchema, data)
        assert errors is not None
        assert 'ports' in errors
    
    def test_invalid_port_range(self):
        """Test validation fails with port out of range"""
        data = {
            'target': 'example.com',
            'ports': '70000',
            'modules': ['network_scan']
        }
        validated, errors = validate_request_data(ScanRequestSchema, data)
        assert errors is not None
        assert 'ports' in errors
    
    def test_valid_multiple_modules(self):
        """Test validation with multiple valid modules"""
        data = {
            'target': 'example.com',
            'modules': [
                'network_scan',
                'dns_enum',
                'whois',
                'ssl_analysis',
                'vuln_scan'
            ]
        }
        validated, errors = validate_request_data(ScanRequestSchema, data)
        assert errors is None
        assert len(validated['modules']) == 5


class TestLoginSchema:
    """Tests for LoginSchema"""
    
    def test_valid_login(self):
        """Test valid login data"""
        data = {
            'username': 'testuser',
            'password': 'testpass123'
        }
        validated, errors = validate_request_data(LoginSchema, data)
        assert errors is None
        assert validated['username'] == 'testuser'
        assert validated['password'] == 'testpass123'
    
    def test_missing_username(self):
        """Test validation fails without username"""
        data = {
            'password': 'testpass123'
        }
        validated, errors = validate_request_data(LoginSchema, data)
        assert errors is not None
        assert 'username' in errors
    
    def test_missing_password(self):
        """Test validation fails without password"""
        data = {
            'username': 'testuser'
        }
        validated, errors = validate_request_data(LoginSchema, data)
        assert errors is not None
        assert 'password' in errors
    
    def test_empty_username(self):
        """Test validation fails with empty username"""
        data = {
            'username': '',
            'password': 'testpass123'
        }
        validated, errors = validate_request_data(LoginSchema, data)
        assert errors is not None
        assert 'username' in errors
    
    def test_invalid_username_characters(self):
        """Test validation fails with invalid username characters"""
        data = {
            'username': 'test@user!',
            'password': 'testpass123'
        }
        validated, errors = validate_request_data(LoginSchema, data)
        assert errors is not None
        assert 'username' in errors
    
    def test_username_with_underscore(self):
        """Test validation allows underscore in username"""
        data = {
            'username': 'test_user',
            'password': 'testpass123'
        }
        validated, errors = validate_request_data(LoginSchema, data)
        assert errors is None
        assert validated['username'] == 'test_user'
    
    def test_username_too_long(self):
        """Test validation fails with username too long"""
        data = {
            'username': 'a' * 81,  # Max is 80
            'password': 'testpass123'
        }
        validated, errors = validate_request_data(LoginSchema, data)
        assert errors is not None
        assert 'username' in errors


class TestScanFilterSchema:
    """Tests for ScanFilterSchema"""
    
    def test_valid_filter_with_status(self):
        """Test valid filter with status"""
        data = {
            'status': 'completed',
            'limit': 20,
            'offset': 0
        }
        validated, errors = validate_request_data(ScanFilterSchema, data)
        assert errors is None
        assert validated['status'] == 'completed'
        assert validated['limit'] == 20
        assert validated['offset'] == 0
    
    def test_default_values(self):
        """Test default values are applied"""
        data = {}
        validated, errors = validate_request_data(ScanFilterSchema, data)
        assert errors is None
        assert validated['limit'] == 10
        assert validated['offset'] == 0
    
    def test_invalid_status(self):
        """Test validation fails with invalid status"""
        data = {
            'status': 'invalid_status'
        }
        validated, errors = validate_request_data(ScanFilterSchema, data)
        assert errors is not None
        assert 'status' in errors
    
    def test_limit_out_of_range_high(self):
        """Test validation fails with limit too high"""
        data = {
            'limit': 101
        }
        validated, errors = validate_request_data(ScanFilterSchema, data)
        assert errors is not None
        assert 'limit' in errors
    
    def test_limit_out_of_range_low(self):
        """Test validation fails with limit too low"""
        data = {
            'limit': 0
        }
        validated, errors = validate_request_data(ScanFilterSchema, data)
        assert errors is not None
        assert 'limit' in errors
    
    def test_negative_offset(self):
        """Test validation fails with negative offset"""
        data = {
            'offset': -1
        }
        validated, errors = validate_request_data(ScanFilterSchema, data)
        assert errors is not None
        assert 'offset' in errors
    
    def test_all_valid_statuses(self):
        """Test all valid status values"""
        statuses = ['pending', 'running', 'completed', 'failed']
        for status in statuses:
            data = {'status': status}
            validated, errors = validate_request_data(ScanFilterSchema, data)
            assert errors is None
            assert validated['status'] == status


class TestValidateRequestDataHelper:
    """Tests for the validate_request_data helper function"""
    
    def test_returns_tuple(self):
        """Test function returns a tuple"""
        data = {'target': 'example.com', 'modules': ['network_scan']}
        result = validate_request_data(ScanRequestSchema, data)
        assert isinstance(result, tuple)
        assert len(result) == 2
    
    def test_success_returns_data_and_none(self):
        """Test successful validation returns data and None"""
        data = {'target': 'example.com', 'modules': ['network_scan']}
        validated, errors = validate_request_data(ScanRequestSchema, data)
        assert validated is not None
        assert errors is None
    
    def test_failure_returns_none_and_errors(self):
        """Test failed validation returns None and errors"""
        data = {'target': 'example.com'}  # Missing modules
        validated, errors = validate_request_data(ScanRequestSchema, data)
        assert validated is None
        assert errors is not None
        assert isinstance(errors, dict)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
