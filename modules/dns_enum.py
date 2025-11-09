"""
DNS Enumeration Module
Handles DNS reconnaissance, subdomain discovery, and DNS record analysis
"""

import dns.resolver
import dns.reversename
import dns.zone
import requests
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import socket

class DNSEnumerator:
    def __init__(self, verbose=False, timeout=5, max_workers=20):
        """
        Initialize DNS enumerator
        
        Args:
            verbose (bool): Enable verbose output
            timeout (int): DNS query timeout in seconds
            max_workers (int): Maximum number of parallel DNS queries (default: 20, reduced from 50)
        """
        self.verbose = verbose
        self.timeout = timeout
        self.max_workers = max_workers
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
        
        # Common subdomains for brute force
        self.common_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'mx', 'm', 'imap',
            'test', 'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news',
            'vpn', 'ns3', 'mail2', 'new', 'mysql', 'old', 'lists', 'support', 'mobile',
            'mx1', 'docs', 'beta', 'shop', 'sql', 'secure', 'demo', 'cp', 'calendar',
            'wiki', 'web', 'media', 'email', 'images', 'img', 'www1', 'intranet',
            'portal', 'video', 'sip', 'dns2', 'api', 'cdn', 'stats', 'dns1', 'ns4',
            'www3', 'dns', 'search', 'staging', 'server', 'mx2', 'chat', 'wap', 'my',
            'svn', 'mail1', 'sites', 'proxy', 'ads', 'host', 'crm', 'cms', 'backup',
            'mx3', 'staging', 'i', 'io', 'go', 'tv'
        ]
    
    def enumerate(self, target):
        """
        Perform comprehensive DNS enumeration
        
        Args:
            target (str): Target domain or IP
            
        Returns:
            dict: DNS enumeration results
        """
        results = {
            'target': target,
            'scan_time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'dns_records': {},
            'subdomains': [],
            'zone_transfer': {},
            'reverse_dns': {},
            'nameservers': []
        }
        
        try:
            # Determine if target is IP or domain
            is_ip = self._is_ip_address(target)
            
            if is_ip:
                # Reverse DNS lookup for IP addresses
                results['reverse_dns'] = self._reverse_dns_lookup(target)
            else:
                # Full DNS enumeration for domains
                results['dns_records'] = self._get_dns_records(target)
                results['nameservers'] = self._get_nameservers(target)
                results['subdomains'] = self._subdomain_enumeration(target)
                results['zone_transfer'] = self._attempt_zone_transfer(target)
        
        except Exception as e:
            results['error'] = f"DNS enumeration error: {str(e)}"
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
    
    def _get_dns_records(self, domain):
        """Retrieve various DNS records for the domain"""
        record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'PTR']
        dns_records = {}
        
        for record_type in record_types:
            try:
                if self.verbose:
                    print(f"    [+] Querying {record_type} records for {domain}")
                
                answers = self.resolver.resolve(domain, record_type)
                records = []
                
                for answer in answers:
                    if record_type == 'MX':
                        records.append({
                            'priority': answer.preference,
                            'exchange': str(answer.exchange)
                        })
                    elif record_type == 'SOA':
                        records.append({
                            'mname': str(answer.mname),
                            'rname': str(answer.rname),
                            'serial': answer.serial,
                            'refresh': answer.refresh,
                            'retry': answer.retry,
                            'expire': answer.expire,
                            'minimum': answer.minimum
                        })
                    else:
                        records.append(str(answer))
                
                dns_records[record_type] = records
                
            except dns.resolver.NXDOMAIN:
                if self.verbose:
                    print(f"    [-] No {record_type} record found for {domain}")
            except dns.resolver.NoAnswer:
                if self.verbose:
                    print(f"    [-] No {record_type} answer for {domain}")
            except Exception as e:
                if self.verbose:
                    print(f"    [ERROR] Error querying {record_type}: {str(e)}")
        
        return dns_records
    
    def _get_nameservers(self, domain):
        """Get authoritative nameservers for the domain"""
        nameservers = []
        
        try:
            ns_records = self.resolver.resolve(domain, 'NS')
            for ns in ns_records:
                ns_str = str(ns).rstrip('.')
                nameservers.append(ns_str)
                
                # Try to get IP address of nameserver
                try:
                    ns_ip = self.resolver.resolve(ns_str, 'A')
                    for ip in ns_ip:
                        nameservers.append(f"{ns_str} ({str(ip)})")
                        break
                except:
                    pass
        
        except Exception as e:
            if self.verbose:
                print(f"    [ERROR] Error getting nameservers: {str(e)}")
        
        return list(set(nameservers))  # Remove duplicates
    
    def _subdomain_enumeration(self, domain):
        """Enumerate subdomains using dictionary attack and DNS queries"""
        subdomains = []
        
        if self.verbose:
            print(f"    [+] Starting subdomain enumeration for {domain}")
        
        def check_subdomain(subdomain):
            full_domain = f"{subdomain}.{domain}"
            try:
                # Try A record
                answers = self.resolver.resolve(full_domain, 'A')
                ips = [str(answer) for answer in answers]
                return {
                    'subdomain': full_domain,
                    'type': 'A',
                    'records': ips
                }
            except:
                try:
                    # Try CNAME record
                    answers = self.resolver.resolve(full_domain, 'CNAME')
                    cnames = [str(answer) for answer in answers]
                    return {
                        'subdomain': full_domain,
                        'type': 'CNAME',
                        'records': cnames
                    }
                except:
                    return None
        
        # Use ThreadPoolExecutor for parallel subdomain checking with controlled concurrency
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_subdomain = {
                executor.submit(check_subdomain, sub): sub 
                for sub in self.common_subdomains
            }
            
            for future in as_completed(future_to_subdomain):
                result = future.result()
                if result:
                    subdomains.append(result)
                    if self.verbose:
                        print(f"    [+] Found subdomain: {result['subdomain']}")
        
        # Additional subdomain discovery methods
        subdomains.extend(self._certificate_transparency_search(domain))
        
        return subdomains
    
    def _certificate_transparency_search(self, domain):
        """Search for subdomains using Certificate Transparency logs"""
        subdomains = []
        
        try:
            if self.verbose:
                print(f"    [+] Searching Certificate Transparency logs for {domain}")
            
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                ct_data = response.json()
                found_domains = set()
                
                for entry in ct_data:
                    name_value = entry.get('name_value', '')
                    if name_value:
                        # Handle multiple domains in name_value
                        domains = name_value.split('\n')
                        for d in domains:
                            d = d.strip().lower()
                            if d.endswith(f'.{domain}') and d not in found_domains:
                                found_domains.add(d)
                
                # Batch verify subdomains in parallel instead of sequentially
                def verify_subdomain(subdomain):
                    try:
                        answers = self.resolver.resolve(subdomain, 'A')
                        ips = [str(answer) for answer in answers]
                        return {
                            'subdomain': subdomain,
                            'type': 'A',
                            'records': ips,
                            'source': 'Certificate Transparency'
                        }
                    except:
                        return None
                
                # Use ThreadPoolExecutor for parallel verification
                with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                    future_to_domain = {
                        executor.submit(verify_subdomain, d): d 
                        for d in found_domains
                    }
                    
                    for future in as_completed(future_to_domain):
                        result = future.result()
                        if result:
                            subdomains.append(result)
        
        except Exception as e:
            if self.verbose:
                print(f"    [ERROR] Certificate Transparency search failed: {str(e)}")
        
        return subdomains
    
    def _attempt_zone_transfer(self, domain):
        """Attempt DNS zone transfer (AXFR)"""
        zone_transfer_results = {
            'attempted': False,
            'successful': False,
            'records': [],
            'nameservers_tested': []
        }
        
        try:
            # Get nameservers for the domain
            nameservers = self._get_nameservers(domain)
            
            for ns in nameservers:
                # Extract just the hostname (remove IP if present)
                ns_hostname = ns.split(' ')[0]
                zone_transfer_results['nameservers_tested'].append(ns_hostname)
                
                try:
                    if self.verbose:
                        print(f"    [+] Attempting zone transfer from {ns_hostname}")
                    
                    zone_transfer_results['attempted'] = True
                    
                    # Attempt zone transfer
                    zone = dns.zone.from_xfr(dns.query.xfr(ns_hostname, domain, timeout=self.timeout))
                    
                    # If we get here, zone transfer was successful
                    zone_transfer_results['successful'] = True
                    
                    # Extract records
                    for name, node in zone.nodes.items():
                        for rdataset in node.rdatasets:
                            record_info = {
                                'name': str(name),
                                'type': dns.rdatatype.to_text(rdataset.rdtype),
                                'ttl': rdataset.ttl,
                                'data': [str(rdata) for rdata in rdataset]
                            }
                            zone_transfer_results['records'].append(record_info)
                    
                    if self.verbose:
                        print(f"    [+] Zone transfer successful! Found {len(zone_transfer_results['records'])} records")
                    
                    break  # Stop after first successful transfer
                
                except Exception as e:
                    if self.verbose:
                        print(f"    [-] Zone transfer failed from {ns_hostname}: {str(e)}")
                    continue
        
        except Exception as e:
            zone_transfer_results['error'] = str(e)
        
        return zone_transfer_results
    
    def _reverse_dns_lookup(self, ip_address):
        """Perform reverse DNS lookup for IP address"""
        reverse_results = {
            'ip_address': ip_address,
            'hostnames': [],
            'ptr_records': []
        }
        
        try:
            if self.verbose:
                print(f"    [+] Performing reverse DNS lookup for {ip_address}")
            
            # Standard reverse DNS lookup
            try:
                hostname = socket.gethostbyaddr(ip_address)[0]
                reverse_results['hostnames'].append(hostname)
            except:
                pass
            
            # PTR record lookup
            try:
                reverse_name = dns.reversename.from_address(ip_address)
                answers = self.resolver.resolve(reverse_name, 'PTR')
                for answer in answers:
                    ptr_record = str(answer).rstrip('.')
                    reverse_results['ptr_records'].append(ptr_record)
            except:
                pass
        
        except Exception as e:
            reverse_results['error'] = str(e)
        
        return reverse_results
    
    def dns_cache_snooping(self, nameserver, domains):
        """Perform DNS cache snooping attack"""
        snooping_results = {
            'nameserver': nameserver,
            'cached_domains': [],
            'method': 'DNS Cache Snooping'
        }
        
        # Configure resolver to use specific nameserver
        custom_resolver = dns.resolver.Resolver()
        custom_resolver.nameservers = [nameserver]
        custom_resolver.timeout = 2
        
        for domain in domains:
            try:
                # Send non-recursive query (RD=0)
                response = custom_resolver.resolve(domain, 'A', raise_on_no_answer=False)
                if response:
                    snooping_results['cached_domains'].append({
                        'domain': domain,
                        'cached': True,
                        'response_time': response.response.time
                    })
            except:
                pass
        
        return snooping_results
