"""
Network Scanner Module
Handles network discovery, host enumeration, port scanning, and service detection
"""

import nmap
import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

class NetworkScanner:
    def __init__(self, timing='T3', verbose=False):
        """
        Initialize the network scanner
        
        Args:
            timing (str): Nmap timing template (T1-T5)
            verbose (bool): Enable verbose output
        """
        self.nm = nmap.PortScanner()
        self.timing = timing
        self.verbose = verbose
        self.results = {}
    
    def scan_target(self, target, ports):
        """
        Perform comprehensive scan on target
        
        Args:
            target (str): Target IP or hostname
            ports (str): Port specification (e.g., '1-1000' or '80,443,8080')
            
        Returns:
            dict: Scan results
        """
        results = {
            'target': target,
            'scan_time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'host_discovery': {},
            'port_scan': {},
            'service_detection': {},
            'os_detection': {}
        }
        
        try:
            # Host discovery
            if self.verbose:
                print(f"    [+] Performing host discovery on {target}")
            
            host_discovery = self._host_discovery(target)
            results['host_discovery'] = host_discovery
            
            if not host_discovery.get('is_up', False):
                if self.verbose:
                    print(f"    [-] Host {target} appears to be down")
                return results
            
            # Port scanning
            if self.verbose:
                print(f"    [+] Scanning ports {ports} on {target}")
            
            port_results = self._port_scan(target, ports)
            results['port_scan'] = port_results
            
            # Service detection on open ports
            open_ports = [p for p in port_results.get('ports', {}) 
                         if port_results['ports'][p]['state'] == 'open']
            
            if open_ports:
                if self.verbose:
                    print(f"    [+] Detecting services on {len(open_ports)} open ports")
                
                service_results = self._service_detection(target, open_ports)
                results['service_detection'] = service_results
                
                # OS detection
                if self.verbose:
                    print(f"    [+] Performing OS detection on {target}")
                
                os_results = self._os_detection(target)
                results['os_detection'] = os_results
            
        except Exception as e:
            results['error'] = f"Scan error: {str(e)}"
            if self.verbose:
                print(f"    [ERROR] {str(e)}")
        
        return results
    
    def _host_discovery(self, target):
        """Perform host discovery using multiple techniques"""
        discovery_results = {
            'is_up': False,
            'ping_response': False,
            'tcp_response': False,
            'response_time': None
        }
        
        try:
            start_time = time.time()
            
            # ICMP ping test
            try:
                self.nm.scan(hosts=target, arguments='-sn')
                if target in self.nm.all_hosts():
                    discovery_results['is_up'] = True
                    discovery_results['ping_response'] = True
            except Exception:
                pass
            
            # TCP SYN test on common ports if ping fails
            if not discovery_results['is_up']:
                try:
                    self.nm.scan(hosts=target, ports='80,443,22,21,25', 
                               arguments=f'-sS -{self.timing}')
                    if target in self.nm.all_hosts():
                        discovery_results['is_up'] = True
                        discovery_results['tcp_response'] = True
                except Exception:
                    pass
            
            discovery_results['response_time'] = round(time.time() - start_time, 2)
            
        except Exception as e:
            discovery_results['error'] = str(e)
        
        return discovery_results
    
    def _port_scan(self, target, ports):
        """Perform comprehensive port scanning"""
        port_results = {
            'scan_type': 'TCP SYN',
            'ports_scanned': ports,
            'ports': {},
            'summary': {
                'total': 0,
                'open': 0,
                'closed': 0,
                'filtered': 0
            }
        }
        
        try:
            # Perform TCP SYN scan
            self.nm.scan(hosts=target, ports=ports, 
                        arguments=f'-sS -{self.timing} --open')
            
            if target in self.nm.all_hosts():
                for port in self.nm[target]['tcp']:
                    port_info = self.nm[target]['tcp'][port]
                    port_results['ports'][port] = {
                        'state': port_info['state'],
                        'reason': port_info.get('reason', ''),
                        'service': port_info.get('name', 'unknown')
                    }
                    
                    # Update summary
                    port_results['summary']['total'] += 1
                    if port_info['state'] == 'open':
                        port_results['summary']['open'] += 1
                    elif port_info['state'] == 'closed':
                        port_results['summary']['closed'] += 1
                    elif port_info['state'] == 'filtered':
                        port_results['summary']['filtered'] += 1
        
        except Exception as e:
            port_results['error'] = str(e)
        
        return port_results
    
    def _service_detection(self, target, ports):
        """Perform detailed service detection and version identification"""
        service_results = {
            'services': {},
            'version_info': {}
        }
        
        try:
            port_list = ','.join(map(str, ports))
            
            # Service version detection
            self.nm.scan(hosts=target, ports=port_list, 
                        arguments=f'-sV -{self.timing}')
            
            if target in self.nm.all_hosts():
                for port in self.nm[target]['tcp']:
                    port_info = self.nm[target]['tcp'][port]
                    
                    service_info = {
                        'name': port_info.get('name', 'unknown'),
                        'product': port_info.get('product', ''),
                        'version': port_info.get('version', ''),
                        'extrainfo': port_info.get('extrainfo', ''),
                        'method': port_info.get('method', ''),
                        'conf': port_info.get('conf', '')
                    }
                    
                    service_results['services'][port] = service_info
                    
                    # Detailed version information
                    if service_info['product'] or service_info['version']:
                        version_string = f"{service_info['product']} {service_info['version']}".strip()
                        service_results['version_info'][port] = version_string
        
        except Exception as e:
            service_results['error'] = str(e)
        
        return service_results
    
    def _os_detection(self, target):
        """Perform operating system detection"""
        os_results = {
            'os_matches': [],
            'fingerprint': None
        }
        
        try:
            # OS detection scan
            self.nm.scan(hosts=target, arguments=f'-O -{self.timing}')
            
            if target in self.nm.all_hosts():
                if 'osmatch' in self.nm[target]:
                    for osmatch in self.nm[target]['osmatch']:
                        os_info = {
                            'name': osmatch.get('name', ''),
                            'accuracy': osmatch.get('accuracy', ''),
                            'line': osmatch.get('line', '')
                        }
                        os_results['os_matches'].append(os_info)
                
                if 'fingerprint' in self.nm[target]:
                    os_results['fingerprint'] = self.nm[target]['fingerprint']
        
        except Exception as e:
            os_results['error'] = str(e)
        
        return os_results
    
    def quick_scan(self, target):
        """Perform a quick scan on common ports"""
        common_ports = '21,22,23,25,53,80,110,111,135,139,143,443,993,995,1723,3306,3389,5432,5900,8080'
        return self.scan_target(target, common_ports)
    
    def custom_scan(self, target, scan_type='sS', arguments=''):
        """Perform custom nmap scan with specified arguments"""
        results = {
            'target': target,
            'scan_type': scan_type,
            'custom_arguments': arguments,
            'results': {}
        }
        
        try:
            full_args = f'-s{scan_type} {arguments}'
            self.nm.scan(hosts=target, arguments=full_args)
            
            if target in self.nm.all_hosts():
                results['results'] = dict(self.nm[target])
        
        except Exception as e:
            results['error'] = str(e)
        
        return results
