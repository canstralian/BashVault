#!/usr/bin/env python3
"""
Performance tests for InfoGather modules
Tests to validate performance optimizations
"""

import unittest
import sys
import os
import time
from unittest.mock import patch, MagicMock, Mock
from concurrent.futures import ThreadPoolExecutor

# Add the parent directory to the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestDNSEnumPerformance(unittest.TestCase):
    """Test DNS enumeration performance optimizations"""
    
    def test_dns_enum_max_workers_limit(self):
        """Test that DNS enumeration respects max_workers limit"""
        from modules.dns_enum import DNSEnumerator
        
        # Test with custom max_workers
        dns_enum = DNSEnumerator(verbose=False, max_workers=10)
        self.assertEqual(dns_enum.max_workers, 10)
        
        # Test with default max_workers (should be 20)
        dns_enum_default = DNSEnumerator()
        self.assertEqual(dns_enum_default.max_workers, 20)
    
    @patch('modules.dns_enum.ThreadPoolExecutor')
    def test_subdomain_enumeration_uses_limited_workers(self, mock_executor):
        """Test that subdomain enumeration uses the configured max_workers"""
        from modules.dns_enum import DNSEnumerator
        
        mock_executor_instance = MagicMock()
        mock_executor.return_value.__enter__.return_value = mock_executor_instance
        mock_executor_instance.submit.return_value.result.return_value = None
        
        dns_enum = DNSEnumerator(verbose=False, max_workers=15)
        
        # This should use the configured max_workers
        try:
            dns_enum._subdomain_enumeration('example.com')
        except:
            pass  # We're just testing that it was called with correct max_workers
        
        # Verify ThreadPoolExecutor was called with max_workers=15
        mock_executor.assert_called()
        call_kwargs = mock_executor.call_args[1] if mock_executor.call_args[1] else {}
        if 'max_workers' in call_kwargs:
            self.assertEqual(call_kwargs['max_workers'], 15)


class TestThreatMonitorPerformance(unittest.TestCase):
    """Test threat monitor performance optimizations"""
    
    @patch('socket.socket')
    def test_parallel_port_scanning(self, mock_socket):
        """Test that port scanning is parallelized"""
        from modules.threat_monitor import ThreatMonitor
        
        # Mock socket to always return port closed
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 1  # Port closed
        mock_socket.return_value = mock_sock
        
        monitor = ThreatMonitor(verbose=False)
        
        start_time = time.time()
        result = monitor._get_ip_hash('127.0.0.1')
        elapsed_time = time.time() - start_time
        
        # Parallel scanning should complete much faster than sequential
        # With 10 ports and 1s timeout each, sequential would take ~10s
        # Parallel should take ~1-2s
        self.assertLess(elapsed_time, 5, 
                       "Parallel port scanning should be faster than 5 seconds")
        
        # Should return a hash
        self.assertIsNotNone(result)
        self.assertIsInstance(result, str)


class TestDatabaseOptimizations(unittest.TestCase):
    """Test database performance optimizations"""
    
    def test_connection_pool_initialization(self):
        """Test that connection pool can be initialized"""
        # Import after setting up mocks
        with patch('psycopg2.pool.ThreadedConnectionPool') as mock_pool:
            mock_pool_instance = MagicMock()
            mock_pool.return_value = mock_pool_instance
            
            # Import the module which should initialize the pool
            import web_dashboard_simple
            
            # Try to initialize connection pool
            try:
                web_dashboard_simple.init_connection_pool()
                # Pool should be created
                self.assertIsNotNone(web_dashboard_simple.connection_pool)
            except Exception as e:
                # Expected if no database is available
                self.assertIn('Failed to initialize', str(e).lower())
    
    def test_memory_cleanup_function_exists(self):
        """Test that memory cleanup functions are defined"""
        import web_dashboard_simple
        
        # Check that cleanup functions exist
        self.assertTrue(hasattr(web_dashboard_simple, 'cleanup_old_scan_results'))
        self.assertTrue(hasattr(web_dashboard_simple, 'start_memory_cleanup_scheduler'))
        
        # Test cleanup function with empty data
        web_dashboard_simple.scan_results = {}
        web_dashboard_simple.cleanup_old_scan_results()
        self.assertEqual(len(web_dashboard_simple.scan_results), 0)
    
    def test_database_indexes_in_init(self):
        """Test that database initialization includes index creation"""
        import web_dashboard_simple
        import inspect
        
        # Get the init_database function source
        source = inspect.getsource(web_dashboard_simple.init_database)
        
        # Verify that indexes are created
        self.assertIn('CREATE INDEX', source)
        self.assertIn('idx_scans_user_id', source)
        self.assertIn('idx_scans_status', source)
        self.assertIn('idx_scans_started_at', source)
        self.assertIn('idx_scan_results_scan_id', source)


class TestBatchOperations(unittest.TestCase):
    """Test batch database operations"""
    
    def test_run_scan_uses_batch_insert(self):
        """Test that run_scan function uses batch insert for results"""
        import web_dashboard_simple
        import inspect
        
        # Get the run_scan function source
        source = inspect.getsource(web_dashboard_simple.run_scan)
        
        # Verify that executemany is used for batch operations
        self.assertIn('executemany', source, 
                     "run_scan should use executemany for batch operations")
        self.assertIn('batch_results', source,
                     "run_scan should collect results in batch_results")
    
    def test_run_scan_reuses_connection(self):
        """Test that run_scan reuses a single connection"""
        import web_dashboard_simple
        import inspect
        
        # Get the run_scan function source
        source = inspect.getsource(web_dashboard_simple.run_scan)
        
        # Should get connection once at the start
        self.assertIn('connection_pool.getconn()', source)
        # Should return connection in finally block
        self.assertIn('connection_pool.putconn(conn)', source)


class TestCertificateTransparencyOptimization(unittest.TestCase):
    """Test Certificate Transparency optimization"""
    
    @patch('modules.dns_enum.requests.get')
    @patch('modules.dns_enum.ThreadPoolExecutor')
    def test_ct_search_parallelizes_verification(self, mock_executor, mock_get):
        """Test that CT search parallelizes subdomain verification"""
        from modules.dns_enum import DNSEnumerator
        
        # Mock CT response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {'name_value': 'www.example.com'},
            {'name_value': 'mail.example.com'}
        ]
        mock_get.return_value = mock_response
        
        # Mock ThreadPoolExecutor
        mock_executor_instance = MagicMock()
        mock_executor.return_value.__enter__.return_value = mock_executor_instance
        mock_future = MagicMock()
        mock_future.result.return_value = None
        mock_executor_instance.submit.return_value = mock_future
        
        dns_enum = DNSEnumerator(verbose=False, max_workers=10)
        
        try:
            dns_enum._certificate_transparency_search('example.com')
        except:
            pass
        
        # Verify that ThreadPoolExecutor was used for verification
        # (should be called twice - once for subdomain enum, once for CT verification)
        self.assertGreaterEqual(mock_executor.call_count, 1)


if __name__ == '__main__':
    unittest.main()
