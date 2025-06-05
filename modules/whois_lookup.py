"""
WHOIS Lookup Module
Handles WHOIS information gathering and domain/IP analysis
"""

import whois
import requests
import socket
import re
from datetime import datetime, timedelta

class WhoisLookup:
    def __init__(self, verbose=False):
        """
        Initialize WHOIS lookup module
        
        Args:
            verbose (bool): Enable verbose output
        """
        self.verbose = verbose
    
    def lookup(self, target):
        """
        Perform comprehensive WHOIS lookup
        
        Args:
            target (str): Target domain or IP address
            
        Returns:
            dict: WHOIS lookup results
        """
        results = {
            'target': target,
            'lookup_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'domain_whois': {},
            'ip_whois': {},
            'registrar_info': {},
            'dns_info': {},
            'security_analysis': {}
        }
        
        try:
            # Determine if target is IP or domain
            is_ip = self._is_ip_address(target)
            
            if is_ip:
                if self.verbose:
                    print(f"    [+] Performing IP WHOIS lookup for {target}")
                results['ip_whois'] = self._ip_whois_lookup(target)
            else:
                if self.verbose:
                    print(f"    [+] Performing domain WHOIS lookup for {target}")
                results['domain_whois'] = self._domain_whois_lookup(target)
                results['registrar_info'] = self._get_registrar_info(target)
                results['dns_info'] = self._get_dns_info(target)
                results['security_analysis'] = self._security_analysis(target)
                
                # Also get IP WHOIS for domain's IP
                try:
                    ip = socket.gethostbyname(target)
                    if self.verbose:
                        print(f"    [+] Performing IP WHOIS lookup for {target} ({ip})")
                    results['ip_whois'] = self._ip_whois_lookup(ip)
                except:
                    pass
        
        except Exception as e:
            results['error'] = f"WHOIS lookup error: {str(e)}"
            if self.verbose:
                print(f"    [ERROR] {str(e)}")
        
        return results
    
    def _is_ip_address(self, target):
        """Check if target is an IP address"""
        try:
            socket.inet_aton(target)
            return True
        except socket.error:
            return False
    
    def _domain_whois_lookup(self, domain):
        """Perform WHOIS lookup for domain"""
        domain_info = {
            'domain_name': domain,
            'registrar': '',
            'creation_date': '',
            'expiration_date': '',
            'updated_date': '',
            'name_servers': [],
            'registrant': {},
            'admin_contact': {},
            'tech_contact': {},
            'status': [],
            'raw_whois': ''
        }
        
        try:
            w = whois.whois(domain)
            
            # Basic domain information
            domain_info['domain_name'] = getattr(w, 'domain_name', domain)
            domain_info['registrar'] = getattr(w, 'registrar', '')
            
            # Handle dates (can be lists or single values)
            creation_date = getattr(w, 'creation_date', None)
            expiration_date = getattr(w, 'expiration_date', None)
            updated_date = getattr(w, 'updated_date', None)
            
            if creation_date:
                domain_info['creation_date'] = str(creation_date[0] if isinstance(creation_date, list) else creation_date)
            if expiration_date:
                domain_info['expiration_date'] = str(expiration_date[0] if isinstance(expiration_date, list) else expiration_date)
            if updated_date:
                domain_info['updated_date'] = str(updated_date[0] if isinstance(updated_date, list) else updated_date)
            
            # Name servers
            name_servers = getattr(w, 'name_servers', [])
            if name_servers:
                domain_info['name_servers'] = [str(ns).lower() for ns in name_servers]
            
            # Contact information
            domain_info['registrant'] = {
                'name': getattr(w, 'name', ''),
                'organization': getattr(w, 'org', ''),
                'address': getattr(w, 'address', ''),
                'city': getattr(w, 'city', ''),
                'state': getattr(w, 'state', ''),
                'postal_code': getattr(w, 'zipcode', ''),
                'country': getattr(w, 'country', ''),
                'email': getattr(w, 'email', ''),
                'phone': getattr(w, 'phone', '')
            }
            
            # Domain status
            status = getattr(w, 'status', [])
            if status:
                domain_info['status'] = status if isinstance(status, list) else [status]
            
            # Raw WHOIS data
            domain_info['raw_whois'] = getattr(w, 'text', '')
            
            # Calculate domain age
            if domain_info['creation_date']:
                try:
                    created = datetime.fromisoformat(domain_info['creation_date'].replace('Z', '+00:00'))
                    age = datetime.now() - created.replace(tzinfo=None)
                    domain_info['domain_age_days'] = age.days
                except:
                    pass
            
            # Calculate days until expiration
            if domain_info['expiration_date']:
                try:
                    expires = datetime.fromisoformat(domain_info['expiration_date'].replace('Z', '+00:00'))
                    days_until_expiry = (expires.replace(tzinfo=None) - datetime.now()).days
                    domain_info['days_until_expiry'] = days_until_expiry
                except:
                    pass
        
        except Exception as e:
            domain_info['error'] = f"Domain WHOIS error: {str(e)}"
        
        return domain_info
    
    def _ip_whois_lookup(self, ip_address):
        """Perform WHOIS lookup for IP address using multiple sources"""
        ip_info = {
            'ip_address': ip_address,
            'network': '',
            'country': '',
            'organization': '',
            'abuse_contact': '',
            'allocation_date': '',
            'asn': '',
            'asn_description': '',
            'raw_whois': ''
        }
        
        # Try multiple WHOIS sources
        sources = [
            self._whois_arin,
            self._whois_ripe,
            self._whois_apnic,
            self._whois_generic
        ]
        
        for source_func in sources:
            try:
                result = source_func(ip_address)
                if result and not result.get('error'):
                    ip_info.update(result)
                    break
            except:
                continue
        
        # Additional IP information from IP geolocation APIs
        try:
            geo_info = self._get_ip_geolocation(ip_address)
            ip_info.update(geo_info)
        except:
            pass
        
        return ip_info
    
    def _whois_arin(self, ip_address):
        """Query ARIN WHOIS database"""
        try:
            import subprocess
            result = subprocess.run(['whois', '-h', 'whois.arin.net', ip_address], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                return self._parse_arin_whois(result.stdout)
        except:
            pass
        return {'error': 'ARIN query failed'}
    
    def _whois_ripe(self, ip_address):
        """Query RIPE WHOIS database"""
        try:
            import subprocess
            result = subprocess.run(['whois', '-h', 'whois.ripe.net', ip_address], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                return self._parse_ripe_whois(result.stdout)
        except:
            pass
        return {'error': 'RIPE query failed'}
    
    def _whois_apnic(self, ip_address):
        """Query APNIC WHOIS database"""
        try:
            import subprocess
            result = subprocess.run(['whois', '-h', 'whois.apnic.net', ip_address], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                return self._parse_apnic_whois(result.stdout)
        except:
            pass
        return {'error': 'APNIC query failed'}
    
    def _whois_generic(self, ip_address):
        """Generic WHOIS query"""
        try:
            import subprocess
            result = subprocess.run(['whois', ip_address], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                return self._parse_generic_whois(result.stdout)
        except:
            pass
        return {'error': 'Generic WHOIS query failed'}
    
    def _parse_arin_whois(self, whois_text):
        """Parse ARIN WHOIS response"""
        info = {'raw_whois': whois_text}
        
        patterns = {
            'organization': r'Organization:\s*(.+)',
            'network': r'NetRange:\s*(.+)',
            'country': r'Country:\s*(.+)',
            'abuse_contact': r'OrgAbuseEmail:\s*(.+)',
            'allocation_date': r'RegDate:\s*(.+)'
        }
        
        for key, pattern in patterns.items():
            match = re.search(pattern, whois_text, re.IGNORECASE)
            if match:
                info[key] = match.group(1).strip()
        
        return info
    
    def _parse_ripe_whois(self, whois_text):
        """Parse RIPE WHOIS response"""
        info = {'raw_whois': whois_text}
        
        patterns = {
            'organization': r'org-name:\s*(.+)',
            'network': r'inetnum:\s*(.+)',
            'country': r'country:\s*(.+)',
            'abuse_contact': r'abuse-mailbox:\s*(.+)'
        }
        
        for key, pattern in patterns.items():
            match = re.search(pattern, whois_text, re.IGNORECASE)
            if match:
                info[key] = match.group(1).strip()
        
        return info
    
    def _parse_apnic_whois(self, whois_text):
        """Parse APNIC WHOIS response"""
        info = {'raw_whois': whois_text}
        
        patterns = {
            'organization': r'org-name:\s*(.+)',
            'network': r'inetnum:\s*(.+)',
            'country': r'country:\s*(.+)',
            'abuse_contact': r'abuse-mailbox:\s*(.+)'
        }
        
        for key, pattern in patterns.items():
            match = re.search(pattern, whois_text, re.IGNORECASE)
            if match:
                info[key] = match.group(1).strip()
        
        return info
    
    def _parse_generic_whois(self, whois_text):
        """Parse generic WHOIS response"""
        info = {'raw_whois': whois_text}
        
        # Extract common fields with flexible patterns
        lines = whois_text.split('\n')
        for line in lines:
            line = line.strip()
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip().lower()
                value = value.strip()
                
                if 'org' in key and not info.get('organization'):
                    info['organization'] = value
                elif 'country' in key and not info.get('country'):
                    info['country'] = value
                elif 'abuse' in key and 'email' in key and not info.get('abuse_contact'):
                    info['abuse_contact'] = value
                elif 'net' in key and 'range' in key and not info.get('network'):
                    info['network'] = value
        
        return info
    
    def _get_ip_geolocation(self, ip_address):
        """Get IP geolocation information"""
        geo_info = {
            'geolocation': {},
            'isp': '',
            'hosting_provider': ''
        }
        
        try:
            # Use ip-api.com for geolocation (free tier)
            response = requests.get(f'http://ip-api.com/json/{ip_address}', timeout=5)
            if response.status_code == 200:
                data = response.json()
                geo_info['geolocation'] = {
                    'country': data.get('country', ''),
                    'region': data.get('regionName', ''),
                    'city': data.get('city', ''),
                    'latitude': data.get('lat', ''),
                    'longitude': data.get('lon', ''),
                    'timezone': data.get('timezone', ''),
                    'isp': data.get('isp', ''),
                    'organization': data.get('org', ''),
                    'as': data.get('as', '')
                }
                geo_info['isp'] = data.get('isp', '')
        except:
            pass
        
        return geo_info
    
    def _get_registrar_info(self, domain):
        """Get detailed registrar information"""
        registrar_info = {
            'registrar_name': '',
            'registrar_url': '',
            'registrar_iana_id': '',
            'registrar_abuse_contact': ''
        }
        
        try:
            w = whois.whois(domain)
            registrar_info['registrar_name'] = getattr(w, 'registrar', '')
            registrar_info['registrar_url'] = getattr(w, 'registrar_url', '')
        except:
            pass
        
        return registrar_info
    
    def _get_dns_info(self, domain):
        """Get DNS-related information"""
        dns_info = {
            'mx_records': [],
            'txt_records': [],
            'spf_record': '',
            'dmarc_record': '',
            'dkim_records': []
        }
        
        try:
            import dns.resolver
            resolver = dns.resolver.Resolver()
            
            # MX records
            try:
                mx_records = resolver.resolve(domain, 'MX')
                for mx in mx_records:
                    dns_info['mx_records'].append({
                        'priority': mx.preference,
                        'exchange': str(mx.exchange)
                    })
            except:
                pass
            
            # TXT records
            try:
                txt_records = resolver.resolve(domain, 'TXT')
                for txt in txt_records:
                    txt_str = str(txt).strip('"')
                    dns_info['txt_records'].append(txt_str)
                    
                    # Check for SPF
                    if txt_str.startswith('v=spf1'):
                        dns_info['spf_record'] = txt_str
            except:
                pass
            
            # DMARC record
            try:
                dmarc_records = resolver.resolve(f'_dmarc.{domain}', 'TXT')
                for dmarc in dmarc_records:
                    dmarc_str = str(dmarc).strip('"')
                    if dmarc_str.startswith('v=DMARC1'):
                        dns_info['dmarc_record'] = dmarc_str
            except:
                pass
        
        except:
            pass
        
        return dns_info
    
    def _security_analysis(self, domain):
        """Perform security analysis on domain"""
        security_info = {
            'domain_reputation': {},
            'security_flags': [],
            'certificate_info': {},
            'security_headers': {}
        }
        
        # Check domain age for suspicious activity
        try:
            w = whois.whois(domain)
            creation_date = getattr(w, 'creation_date', None)
            if creation_date:
                created = creation_date[0] if isinstance(creation_date, list) else creation_date
                if isinstance(created, datetime):
                    days_old = (datetime.now() - created).days
                    if days_old < 30:
                        security_info['security_flags'].append('Recently registered domain (less than 30 days)')
                    elif days_old < 90:
                        security_info['security_flags'].append('Young domain (less than 90 days)')
        except:
            pass
        
        # Check for privacy protection
        try:
            w = whois.whois(domain)
            registrant_name = getattr(w, 'name', '')
            if any(privacy_term in str(registrant_name).lower() for privacy_term in 
                   ['privacy', 'protection', 'proxy', 'whoisguard', 'private']):
                security_info['security_flags'].append('Domain privacy protection enabled')
        except:
            pass
        
        return security_info
    
    def bulk_whois_lookup(self, targets):
        """Perform WHOIS lookup on multiple targets"""
        results = {}
        
        for target in targets:
            if self.verbose:
                print(f"[+] Processing WHOIS lookup for {target}")
            results[target] = self.lookup(target)
        
        return results
