"""
SSL/TLS Certificate Analysis Module
Handles SSL certificate analysis, vulnerability checks, and configuration assessment
"""

import ssl
import socket
import datetime
import requests
from urllib.parse import urlparse
import concurrent.futures
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import hashlib

class SSLAnalyzer:
    def __init__(self, verbose=False, timeout=10):
        """
        Initialize SSL analyzer
        
        Args:
            verbose (bool): Enable verbose output
            timeout (int): Connection timeout in seconds
        """
        self.verbose = verbose
        self.timeout = timeout
        
        # Common SSL/TLS ports to check
        self.ssl_ports = [443, 993, 995, 465, 587, 636, 989, 990, 992, 5061]
        
        # Weak cipher suites
        self.weak_ciphers = [
            'RC4', 'DES', '3DES', 'MD5', 'SHA1', 'NULL', 'EXPORT', 'ANON'
        ]
    
    def analyze(self, target, ports=None):
        """
        Perform comprehensive SSL/TLS analysis
        
        Args:
            target (str): Target hostname or IP
            ports (list): List of ports to check (defaults to common SSL ports)
            
        Returns:
            dict: SSL analysis results
        """
        results = {
            'target': target,
            'analysis_time': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'ssl_services': {},
            'certificates': {},
            'vulnerabilities': [],
            'security_assessment': {}
        }
        
        # Use provided ports or default SSL ports
        ports_to_check = ports if ports else self.ssl_ports
        
        try:
            if self.verbose:
                print(f"    [+] Starting SSL analysis on {target}")
            
            # Check each port for SSL services
            ssl_services = self._discover_ssl_services(target, ports_to_check)
            results['ssl_services'] = ssl_services
            
            # Analyze certificates for each SSL service
            for port, service_info in ssl_services.items():
                if service_info.get('ssl_enabled'):
                    if self.verbose:
                        print(f"    [+] Analyzing SSL certificate on port {port}")
                    
                    cert_analysis = self._analyze_certificate(target, port)
                    results['certificates'][port] = cert_analysis
                    
                    # Check for SSL/TLS vulnerabilities
                    vuln_check = self._check_vulnerabilities(target, port)
                    if vuln_check:
                        results['vulnerabilities'].extend(vuln_check)
            
            # Generate security assessment
            results['security_assessment'] = self._generate_security_assessment(results)
        
        except Exception as e:
            results['error'] = f"SSL analysis error: {str(e)}"
            if self.verbose:
                print(f"    [ERROR] {str(e)}")
        
        return results
    
    def _discover_ssl_services(self, target, ports):
        """Discover SSL-enabled services on specified ports"""
        ssl_services = {}
        
        def check_ssl_port(port):
            service_info = {
                'port': port,
                'ssl_enabled': False,
                'ssl_version': None,
                'cipher_suite': None,
                'error': None
            }
            
            try:
                # Create SSL context
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                # Attempt SSL connection
                with socket.create_connection((target, port), timeout=self.timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=target) as ssock:
                        service_info['ssl_enabled'] = True
                        service_info['ssl_version'] = ssock.version()
                        service_info['cipher_suite'] = ssock.cipher()
                        
                        if self.verbose:
                            print(f"    [+] SSL service found on port {port}: {ssock.version()}")
            
            except ssl.SSLError as e:
                service_info['error'] = f"SSL Error: {str(e)}"
            except socket.timeout:
                service_info['error'] = "Connection timeout"
            except ConnectionRefusedError:
                service_info['error'] = "Connection refused"
            except Exception as e:
                service_info['error'] = f"Error: {str(e)}"
            
            return port, service_info
        
        # Use ThreadPoolExecutor for parallel port checking
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_port = {executor.submit(check_ssl_port, port): port for port in ports}
            
            for future in concurrent.futures.as_completed(future_to_port):
                port, service_info = future.result()
                ssl_services[port] = service_info
        
        return ssl_services
    
    def _analyze_certificate(self, target, port):
        """Analyze SSL certificate in detail"""
        cert_info = {
            'port': port,
            'certificate_details': {},
            'chain_details': [],
            'validation_results': {},
            'security_issues': []
        }
        
        try:
            # Get certificate
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((target, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    # Get peer certificate
                    der_cert = ssock.getpeercert_der()
                    pem_cert = ssl.DER_cert_to_PEM_cert(der_cert)
                    
                    # Parse certificate using cryptography library
                    cert = x509.load_pem_x509_certificate(pem_cert.encode(), default_backend())
                    
                    # Extract certificate details
                    cert_info['certificate_details'] = self._extract_cert_details(cert)
                    
                    # Get certificate chain
                    cert_chain = ssock.getpeercert_chain()
                    if cert_chain:
                        for i, chain_cert in enumerate(cert_chain):
                            chain_pem = ssl.DER_cert_to_PEM_cert(chain_cert)
                            chain_cert_obj = x509.load_pem_x509_certificate(chain_pem.encode(), default_backend())
                            chain_details = self._extract_cert_details(chain_cert_obj)
                            chain_details['position_in_chain'] = i
                            cert_info['chain_details'].append(chain_details)
                    
                    # Validate certificate
                    cert_info['validation_results'] = self._validate_certificate(cert, target)
                    
                    # Check for security issues
                    cert_info['security_issues'] = self._check_cert_security_issues(cert)
        
        except Exception as e:
            cert_info['error'] = f"Certificate analysis error: {str(e)}"
        
        return cert_info
    
    def _extract_cert_details(self, cert):
        """Extract detailed information from X.509 certificate"""
        details = {}
        
        try:
            # Basic certificate information
            details['version'] = cert.version.name
            details['serial_number'] = str(cert.serial_number)
            details['signature_algorithm'] = cert.signature_algorithm_oid._name
            
            # Subject information
            subject = cert.subject
            details['subject'] = {}
            for attribute in subject:
                details['subject'][attribute.oid._name] = attribute.value
            
            # Issuer information
            issuer = cert.issuer
            details['issuer'] = {}
            for attribute in issuer:
                details['issuer'][attribute.oid._name] = attribute.value
            
            # Validity period
            details['not_valid_before'] = cert.not_valid_before.strftime('%Y-%m-%d %H:%M:%S')
            details['not_valid_after'] = cert.not_valid_after.strftime('%Y-%m-%d %H:%M:%S')
            
            # Calculate days until expiration
            days_until_expiry = (cert.not_valid_after - datetime.datetime.now()).days
            details['days_until_expiry'] = days_until_expiry
            
            # Public key information
            public_key = cert.public_key()
            details['public_key'] = {
                'algorithm': type(public_key).__name__,
                'key_size': public_key.key_size if hasattr(public_key, 'key_size') else 'Unknown'
            }
            
            # Extensions
            details['extensions'] = {}
            for extension in cert.extensions:
                ext_name = extension.oid._name
                try:
                    if ext_name == 'subjectAltName':
                        alt_names = []
                        for name in extension.value:
                            alt_names.append(f"{name.__class__.__name__}: {name.value}")
                        details['extensions'][ext_name] = alt_names
                    elif ext_name == 'keyUsage':
                        key_usage = []
                        for usage in ['digital_signature', 'key_agreement', 'key_cert_sign', 
                                     'key_encipherment', 'data_encipherment', 'content_commitment',
                                     'crl_sign', 'encipher_only', 'decipher_only']:
                            if hasattr(extension.value, usage) and getattr(extension.value, usage):
                                key_usage.append(usage)
                        details['extensions'][ext_name] = key_usage
                    else:
                        details['extensions'][ext_name] = str(extension.value)
                except:
                    details['extensions'][ext_name] = 'Unable to parse'
            
            # Certificate fingerprints (used for identification, not security validation)
            cert_der = cert.public_bytes(encoding=x509.Encoding.DER)
            details['fingerprints'] = {
                'sha1': hashlib.sha1(cert_der, usedforsecurity=False).hexdigest(),  # nosec B324
                'sha256': hashlib.sha256(cert_der).hexdigest(),  # SHA256 is secure
                'md5': hashlib.md5(cert_der, usedforsecurity=False).hexdigest()  # nosec B324
            }
        
        except Exception as e:
            details['extraction_error'] = str(e)
        
        return details
    
    def _validate_certificate(self, cert, hostname):
        """Validate certificate against hostname and other criteria"""
        validation = {
            'hostname_match': False,
            'self_signed': False,
            'expired': False,
            'not_yet_valid': False,
            'weak_signature': False,
            'revocation_status': 'Unknown'
        }
        
        try:
            now = datetime.datetime.now()
            
            # Check if certificate is expired or not yet valid
            validation['expired'] = cert.not_valid_after < now
            validation['not_yet_valid'] = cert.not_valid_before > now
            
            # Check if self-signed
            validation['self_signed'] = cert.issuer == cert.subject
            
            # Check hostname match
            try:
                # Check subject common name
                subject_cn = None
                for attribute in cert.subject:
                    if attribute.oid._name == 'commonName':
                        subject_cn = attribute.value
                        break
                
                if subject_cn and (subject_cn == hostname or 
                                  (subject_cn.startswith('*.') and 
                                   hostname.endswith(subject_cn[2:]))):
                    validation['hostname_match'] = True
                
                # Check Subject Alternative Names
                try:
                    san_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                    for name in san_ext.value:
                        if hasattr(name, 'value'):
                            san_value = name.value
                            if (san_value == hostname or 
                                (san_value.startswith('*.') and 
                                 hostname.endswith(san_value[2:]))):
                                validation['hostname_match'] = True
                                break
                except:
                    pass
            except:
                pass
            
            # Check for weak signature algorithm
            weak_algorithms = ['md5', 'sha1']
            if any(weak_alg in cert.signature_algorithm_oid._name.lower() for weak_alg in weak_algorithms):
                validation['weak_signature'] = True
        
        except Exception as e:
            validation['validation_error'] = str(e)
        
        return validation
    
    def _check_cert_security_issues(self, cert):
        """Check for various certificate security issues"""
        issues = []
        
        try:
            now = datetime.datetime.now()
            
            # Check expiration
            days_until_expiry = (cert.not_valid_after - now).days
            if days_until_expiry < 0:
                issues.append("Certificate has expired")
            elif days_until_expiry < 30:
                issues.append(f"Certificate expires soon ({days_until_expiry} days)")
            
            # Check certificate age
            cert_age = (now - cert.not_valid_before).days
            if cert_age > 1095:  # 3 years
                issues.append("Certificate is very old (over 3 years)")
            
            # Check key size
            public_key = cert.public_key()
            if hasattr(public_key, 'key_size'):
                if public_key.key_size < 2048:
                    issues.append(f"Weak key size: {public_key.key_size} bits")
            
            # Check signature algorithm
            sig_alg = cert.signature_algorithm_oid._name.lower()
            if 'md5' in sig_alg:
                issues.append("Uses weak MD5 signature algorithm")
            elif 'sha1' in sig_alg:
                issues.append("Uses weak SHA1 signature algorithm")
            
            # Check if self-signed
            if cert.issuer == cert.subject:
                issues.append("Self-signed certificate")
            
            # Check for missing extensions
            try:
                cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            except:
                issues.append("Missing Subject Alternative Name extension")
        
        except Exception as e:
            issues.append(f"Security check error: {str(e)}")
        
        return issues
    
    def _check_vulnerabilities(self, target, port):
        """Check for SSL/TLS vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Check for weak protocols
            weak_protocols = ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']
            for protocol in weak_protocols:
                if self._test_ssl_protocol(target, port, protocol):
                    vulnerabilities.append({
                        'vulnerability': f'Weak protocol {protocol} supported',
                        'severity': 'High' if protocol in ['SSLv2', 'SSLv3'] else 'Medium',
                        'description': f'Server supports the weak {protocol} protocol'
                    })
            
            # Check for weak cipher suites
            weak_ciphers = self._check_weak_ciphers(target, port)
            for cipher in weak_ciphers:
                vulnerabilities.append({
                    'vulnerability': f'Weak cipher suite: {cipher}',
                    'severity': 'Medium',
                    'description': f'Server supports weak cipher suite {cipher}'
                })
            
            # Check for specific vulnerabilities
            vuln_tests = [
                ('POODLE', self._test_poodle),
                ('BEAST', self._test_beast),
                ('CRIME', self._test_crime),
                ('BREACH', self._test_breach),
                ('Heartbleed', self._test_heartbleed)
            ]
            
            for vuln_name, test_func in vuln_tests:
                try:
                    if test_func(target, port):
                        vulnerabilities.append({
                            'vulnerability': vuln_name,
                            'severity': 'High',
                            'description': f'Server is vulnerable to {vuln_name} attack'
                        })
                except:
                    pass
        
        except Exception as e:
            vulnerabilities.append({
                'vulnerability': 'Vulnerability scan error',
                'severity': 'Unknown',
                'description': str(e)
            })
        
        return vulnerabilities
    
    def _test_ssl_protocol(self, target, port, protocol):
        """Test if a specific SSL/TLS protocol is supported"""
        try:
            protocol_map = {
                'SSLv2': ssl.PROTOCOL_SSLv23,  # Will try SSLv2 if available
                'SSLv3': ssl.PROTOCOL_SSLv23,  # Will try SSLv3 if available  
                'TLSv1': ssl.PROTOCOL_TLSv1 if hasattr(ssl, 'PROTOCOL_TLSv1') else ssl.PROTOCOL_SSLv23,
                'TLSv1.1': ssl.PROTOCOL_TLSv1_1 if hasattr(ssl, 'PROTOCOL_TLSv1_1') else ssl.PROTOCOL_SSLv23,
            }
            
            if protocol not in protocol_map:
                return False
            
            context = ssl.SSLContext(protocol_map[protocol])
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((target, port), timeout=5) as sock:
                with context.wrap_socket(sock) as ssock:
                    return ssock.version() == protocol
        except:
            return False
    
    def _check_weak_ciphers(self, target, port):
        """Check for weak cipher suites"""
        weak_ciphers_found = []
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((target, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cipher_info = ssock.cipher()
                    if cipher_info:
                        cipher_name = cipher_info[0]
                        for weak_cipher in self.weak_ciphers:
                            if weak_cipher.upper() in cipher_name.upper():
                                weak_ciphers_found.append(cipher_name)
        except:
            pass
        
        return weak_ciphers_found
    
    def _test_poodle(self, target, port):
        """Test for POODLE vulnerability"""
        # Simplified POODLE test - checks if SSLv3 is enabled
        return self._test_ssl_protocol(target, port, 'SSLv3')
    
    def _test_beast(self, target, port):
        """Test for BEAST vulnerability"""
        # BEAST affects TLS 1.0 with CBC ciphers
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLSv1 if hasattr(ssl, 'PROTOCOL_TLSv1') else ssl.PROTOCOL_SSLv23)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((target, port), timeout=5) as sock:
                with context.wrap_socket(sock) as ssock:
                    if ssock.version() == 'TLSv1':
                        cipher = ssock.cipher()
                        if cipher and 'CBC' in cipher[0]:
                            return True
        except:
            pass
        return False
    
    def _test_crime(self, target, port):
        """Test for CRIME vulnerability"""
        # CRIME exploits TLS compression
        try:
            # This is a simplified test - actual CRIME testing is more complex
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((target, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    # Check if compression is enabled (simplified)
                    return hasattr(ssock, 'compression') and ssock.compression() is not None
        except:
            pass
        return False
    
    def _test_breach(self, target, port):
        """Test for BREACH vulnerability"""
        # BREACH exploits HTTP compression over HTTPS
        try:
            if port == 443:  # Only test HTTPS
                response = requests.get(f'https://{target}', timeout=5, verify=True)
                content_encoding = response.headers.get('content-encoding', '')
                return 'gzip' in content_encoding.lower() or 'deflate' in content_encoding.lower()
        except:
            pass
        return False
    
    def _test_heartbleed(self, target, port):
        """Test for Heartbleed vulnerability"""
        # Simplified Heartbleed test - this is a basic check
        # Real Heartbleed testing requires sending specific TLS heartbeat packets
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((target, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    # Check for OpenSSL version in server response
                    # This is not a definitive test but can indicate vulnerable versions
                    return False  # Placeholder - real implementation would be more complex
        except:
            pass
        return False
    
    def _generate_security_assessment(self, results):
        """Generate overall security assessment"""
        assessment = {
            'overall_score': 100,
            'security_level': 'Unknown',
            'recommendations': [],
            'critical_issues': 0,
            'high_issues': 0,
            'medium_issues': 0,
            'low_issues': 0
        }
        
        # Count vulnerabilities by severity
        for vuln in results.get('vulnerabilities', []):
            severity = vuln.get('severity', 'Unknown').lower()
            if severity == 'critical':
                assessment['critical_issues'] += 1
                assessment['overall_score'] -= 30
            elif severity == 'high':
                assessment['high_issues'] += 1
                assessment['overall_score'] -= 20
            elif severity == 'medium':
                assessment['medium_issues'] += 1
                assessment['overall_score'] -= 10
            elif severity == 'low':
                assessment['low_issues'] += 1
                assessment['overall_score'] -= 5
        
        # Check certificate issues
        for port, cert_info in results.get('certificates', {}).items():
            for issue in cert_info.get('security_issues', []):
                assessment['overall_score'] -= 5
                if 'expired' in issue.lower():
                    assessment['recommendations'].append('Replace expired certificates immediately')
                elif 'weak' in issue.lower():
                    assessment['recommendations'].append('Upgrade to stronger cryptographic algorithms')
        
        # Ensure score doesn't go below 0
        assessment['overall_score'] = max(0, assessment['overall_score'])
        
        # Determine security level
        if assessment['overall_score'] >= 90:
            assessment['security_level'] = 'Excellent'
        elif assessment['overall_score'] >= 80:
            assessment['security_level'] = 'Good'
        elif assessment['overall_score'] >= 70:
            assessment['security_level'] = 'Fair'
        elif assessment['overall_score'] >= 60:
            assessment['security_level'] = 'Poor'
        else:
            assessment['security_level'] = 'Critical'
        
        # Add general recommendations
        if assessment['critical_issues'] > 0 or assessment['high_issues'] > 0:
            assessment['recommendations'].append('Address critical and high severity vulnerabilities immediately')
        
        if not assessment['recommendations']:
            assessment['recommendations'].append('SSL/TLS configuration appears secure')
        
        return assessment
