
import unittest
import sys
import os
from unittest.mock import patch, MagicMock

# Add the parent directory to the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

class TestModules(unittest.TestCase):
    """Test cases for individual modules"""
    
    def test_report_generator(self):
        """Test report generator functionality"""
        from modules.report_generator import ReportGenerator
        
        generator = ReportGenerator()
        self.assertIsNotNone(generator)
        
        # Test report data structure
        test_data = {
            'target': '127.0.0.1',
            'scan_time': '2024-01-01 12:00:00',
            'results': {}
        }
        
        # Test text report generation
        text_report = generator.generate_text_report(test_data)
        self.assertIsInstance(text_report, str)
        self.assertIn('127.0.0.1', text_report)
    
    def test_vulnerability_scanner(self):
        """Test vulnerability scanner initialization"""
        from modules.vulnerability_scanner import VulnerabilityScanner
        
        scanner = VulnerabilityScanner()
        self.assertIsNotNone(scanner)
    
    @patch('modules.advanced_dns.requests.get')
    def test_advanced_dns(self, mock_get):
        """Test advanced DNS module"""
        from modules.advanced_dns import AdvancedDNS
        
        mock_response = MagicMock()
        mock_response.json.return_value = {'Answer': [{'data': '127.0.0.1'}]}
        mock_get.return_value = mock_response
        
        dns = AdvancedDNS()
        self.assertIsNotNone(dns)
    
    def test_cloud_discovery(self):
        """Test cloud discovery module initialization"""
        from modules.cloud_discovery import CloudDiscovery
        
        discovery = CloudDiscovery()
        self.assertIsNotNone(discovery)
    
    def test_social_engineer(self):
        """Test social engineering module initialization"""
        from modules.social_engineer import SocialEngineer
        
        social = SocialEngineer()
        self.assertIsNotNone(social)

class TestUtilities(unittest.TestCase):
    """Test utility functions"""
    
    def test_network_utils(self):
        """Test network utility functions"""
        from utils.network_utils import is_valid_ip, is_valid_domain
        
        # Test IP validation
        self.assertTrue(is_valid_ip("192.168.1.1"))
        self.assertTrue(is_valid_ip("127.0.0.1"))
        self.assertFalse(is_valid_ip("999.999.999.999"))
        self.assertFalse(is_valid_ip("not.an.ip"))
        
        # Test domain validation
        self.assertTrue(is_valid_domain("example.com"))
        self.assertTrue(is_valid_domain("subdomain.example.com"))
        self.assertFalse(is_valid_domain("invalid..domain"))
        self.assertFalse(is_valid_domain(""))
    
    def test_validation(self):
        """Test validation utilities"""
        from utils.validation import sanitize_input, validate_port_range
        
        # Test input sanitization
        self.assertEqual(sanitize_input("normal_input"), "normal_input")
        self.assertEqual(sanitize_input("input;with;semicolons"), "inputwithsemicolons")
        
        # Test port range validation
        self.assertTrue(validate_port_range("80"))
        self.assertTrue(validate_port_range("1-1000"))
        self.assertTrue(validate_port_range("80,443,8080"))
        self.assertFalse(validate_port_range("70000"))
        self.assertFalse(validate_port_range("invalid"))

if __name__ == '__main__':
    unittest.main()
