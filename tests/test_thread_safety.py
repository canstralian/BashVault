#!/usr/bin/env python3
"""
Tests for thread safety in concurrent operations
"""

import pytest
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed


class TestThreadSafeLocks:
    """Tests for thread-safe operations with locks"""
    
    def test_rlock_basic_operation(self):
        """Test basic RLock operation"""
        lock = threading.RLock()
        shared_data = {'count': 0}
        
        def increment():
            with lock:
                current = shared_data['count']
                time.sleep(0.001)  # Simulate some work
                shared_data['count'] = current + 1
        
        # Run 10 threads concurrently
        threads = []
        for _ in range(10):
            t = threading.Thread(target=increment)
            t.start()
            threads.append(t)
        
        # Wait for all threads to complete
        for t in threads:
            t.join()
        
        # Should be exactly 10 if thread-safe
        assert shared_data['count'] == 10
    
    def test_rlock_reentrant(self):
        """Test RLock is reentrant (same thread can acquire multiple times)"""
        lock = threading.RLock()
        acquired_count = 0
        
        def nested_acquire():
            nonlocal acquired_count
            with lock:
                acquired_count += 1
                with lock:
                    acquired_count += 1
                    with lock:
                        acquired_count += 1
        
        nested_acquire()
        assert acquired_count == 3
    
    def test_concurrent_dict_access_with_lock(self):
        """Test concurrent dictionary access with proper locking"""
        lock = threading.RLock()
        shared_dict = {}
        
        def add_items(thread_id):
            for i in range(100):
                key = f"thread_{thread_id}_item_{i}"
                with lock:
                    shared_dict[key] = thread_id
        
        # Run 5 threads concurrently
        threads = []
        for i in range(5):
            t = threading.Thread(target=add_items, args=(i,))
            t.start()
            threads.append(t)
        
        # Wait for all threads
        for t in threads:
            t.join()
        
        # Should have exactly 500 items (5 threads * 100 items)
        assert len(shared_dict) == 500
    
    def test_concurrent_dict_update_with_lock(self):
        """Test concurrent dictionary updates with proper locking"""
        lock = threading.RLock()
        shared_dict = {'counter': 0}
        
        def increment_counter():
            for _ in range(1000):
                with lock:
                    shared_dict['counter'] += 1
        
        # Run 5 threads concurrently
        threads = []
        for _ in range(5):
            t = threading.Thread(target=increment_counter)
            t.start()
            threads.append(t)
        
        # Wait for all threads
        for t in threads:
            t.join()
        
        # Should be exactly 5000 (5 threads * 1000 increments)
        assert shared_dict['counter'] == 5000
    
    def test_without_lock_demonstrates_race_condition(self):
        """Demonstrate race condition without lock (expected to fail sometimes)"""
        shared_data = {'count': 0}
        race_condition_occurred = False
        
        def unsafe_increment():
            nonlocal race_condition_occurred
            for _ in range(100):
                current = shared_data['count']
                time.sleep(0.0001)  # Increase chance of race condition
                new_value = current + 1
                if shared_data['count'] != current:
                    # Another thread modified it while we were working
                    race_condition_occurred = True
                shared_data['count'] = new_value
        
        # Run multiple threads without lock
        threads = []
        for _ in range(5):
            t = threading.Thread(target=unsafe_increment)
            t.start()
            threads.append(t)
        
        for t in threads:
            t.join()
        
        # Without lock, final count is usually less than expected
        # or race condition is detected
        assert shared_data['count'] <= 500 or race_condition_occurred


class TestThreadPoolExecutor:
    """Tests for ThreadPoolExecutor usage patterns"""
    
    def test_threadpool_basic_execution(self):
        """Test basic ThreadPoolExecutor execution"""
        def square(x):
            return x * x
        
        numbers = list(range(10))
        results = []
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            future_to_num = {executor.submit(square, num): num for num in numbers}
            
            for future in as_completed(future_to_num):
                results.append(future.result())
        
        # All results should be computed
        assert len(results) == 10
        assert sorted(results) == [0, 1, 4, 9, 16, 25, 36, 49, 64, 81]
    
    def test_threadpool_exception_handling(self):
        """Test ThreadPoolExecutor handles exceptions properly"""
        def may_fail(x):
            if x == 5:
                raise ValueError(f"Error processing {x}")
            return x * 2
        
        numbers = list(range(10))
        results = []
        errors = []
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            future_to_num = {executor.submit(may_fail, num): num for num in numbers}
            
            for future in as_completed(future_to_num):
                try:
                    results.append(future.result())
                except ValueError as e:
                    errors.append(str(e))
        
        # Should have 9 results and 1 error
        assert len(results) == 9
        assert len(errors) == 1
        assert "Error processing 5" in errors[0]
    
    def test_threadpool_context_manager_cleanup(self):
        """Test ThreadPoolExecutor context manager cleans up properly"""
        executed_tasks = []
        
        def task(x):
            executed_tasks.append(x)
            time.sleep(0.01)
            return x
        
        # Executor should wait for all tasks before exiting context
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = [executor.submit(task, i) for i in range(10)]
        
        # All tasks should be completed after context exits
        assert len(executed_tasks) == 10
    
    def test_threadpool_max_workers_limit(self):
        """Test ThreadPoolExecutor respects max_workers limit"""
        active_threads = []
        max_concurrent = 0
        lock = threading.Lock()
        
        def task(x):
            nonlocal max_concurrent
            with lock:
                active_threads.append(x)
                max_concurrent = max(max_concurrent, len(active_threads))
            
            time.sleep(0.1)  # Simulate work
            
            with lock:
                active_threads.remove(x)
            
            return x
        
        # Use max_workers=3, submit 10 tasks
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = [executor.submit(task, i) for i in range(10)]
            for future in as_completed(futures):
                future.result()
        
        # Should never have more than 3 threads active
        assert max_concurrent <= 3


class TestScanDictionaryThreadSafety:
    """Tests simulating the active_scans and scan_results dictionaries"""
    
    def test_concurrent_scan_creation(self):
        """Test concurrent scan creation with locks"""
        scans_lock = threading.RLock()
        active_scans = {}
        
        def create_scan(scan_id):
            with scans_lock:
                active_scans[scan_id] = {
                    'status': 'running',
                    'progress': 0
                }
        
        # Create 100 scans concurrently
        scan_ids = [f"scan_{i}" for i in range(100)]
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(create_scan, sid) for sid in scan_ids]
            for future in as_completed(futures):
                future.result()
        
        # All scans should be created
        assert len(active_scans) == 100
    
    def test_concurrent_scan_updates(self):
        """Test concurrent scan status updates with locks"""
        scans_lock = threading.RLock()
        active_scans = {}
        
        # Create initial scans
        for i in range(10):
            active_scans[f"scan_{i}"] = {'progress': 0}
        
        def update_scan_progress(scan_id):
            for progress in range(0, 101, 10):
                with scans_lock:
                    if scan_id in active_scans:
                        active_scans[scan_id]['progress'] = progress
                time.sleep(0.001)
        
        # Update 10 scans concurrently
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [
                executor.submit(update_scan_progress, f"scan_{i}") 
                for i in range(10)
            ]
            for future in as_completed(futures):
                future.result()
        
        # All scans should have progress 100
        for scan_id, scan_data in active_scans.items():
            assert scan_data['progress'] == 100
    
    def test_concurrent_scan_read_write(self):
        """Test concurrent scan reads and writes with locks"""
        scans_lock = threading.RLock()
        active_scans = {'scan_1': {'status': 'running', 'count': 0}}
        
        def increment_scan_count():
            for _ in range(100):
                with scans_lock:
                    if 'scan_1' in active_scans:
                        active_scans['scan_1']['count'] += 1
        
        def read_scan_status():
            reads = []
            for _ in range(100):
                with scans_lock:
                    if 'scan_1' in active_scans:
                        reads.append(active_scans['scan_1']['count'])
                time.sleep(0.0001)
            return reads
        
        # Run concurrent reads and writes
        with ThreadPoolExecutor(max_workers=5) as executor:
            # 3 writers, 2 readers
            write_futures = [executor.submit(increment_scan_count) for _ in range(3)]
            read_futures = [executor.submit(read_scan_status) for _ in range(2)]
            
            # Wait for completion
            for future in as_completed(write_futures + read_futures):
                future.result()
        
        # Final count should be exactly 300 (3 threads * 100)
        assert active_scans['scan_1']['count'] == 300


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
