
#!/usr/bin/env python3
"""
Threat Monitor Module
Real-time threat intelligence and monitoring capabilities
"""

import requests
import json
import time
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import hashlib
import sqlite3
import os

class ThreatMonitor:
    def __init__(self, verbose=False):
        """
        Initialize threat monitor
        
        Args:
            verbose (bool): Enable verbose output
        """
        self.verbose = verbose
        self.db_path = 'threat_monitor.db'
        self.monitoring_active = False
        self.monitor_thread = None
        self.asset_cache = {}
        self.vulnerability_feeds = {
            'nvd': 'https://services.nvd.nist.gov/rest/json/cves/2.0',
            'cisa_kev': 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
            'circl_cve': 'https://cve.circl.lu/api/cve'
        }
        
        self._init_database()
    
    def _init_database(self):
        """Initialize threat monitoring database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Asset monitoring table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS monitored_assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                asset_type TEXT NOT NULL,
                asset_value TEXT NOT NULL,
                last_check TIMESTAMP,
                current_hash TEXT,
                status TEXT DEFAULT 'active',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Vulnerability feed table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerability_feed (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT UNIQUE,
                title TEXT,
                description TEXT,
                severity TEXT,
                cvss_score REAL,
                published_date TIMESTAMP,
                affected_products TEXT,
                exploit_available BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Asset changes table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS asset_changes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                asset_id INTEGER,
                change_type TEXT,
                old_value TEXT,
                new_value TEXT,
                detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (asset_id) REFERENCES monitored_assets (id)
            )
        ''')
        
        # Alerts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_type TEXT,
                severity TEXT,
                title TEXT,
                description TEXT,
                asset_id INTEGER,
                cve_id TEXT,
                status TEXT DEFAULT 'new',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def add_monitored_asset(self, asset_type: str, asset_value: str) -> bool:
        """
        Add an asset to continuous monitoring
        
        Args:
            asset_type (str): Type of asset (domain, ip, service, etc.)
            asset_value (str): Asset identifier
            
        Returns:
            bool: Success status
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Check if asset already exists
            cursor.execute(
                'SELECT id FROM monitored_assets WHERE asset_type = ? AND asset_value = ?',
                (asset_type, asset_value)
            )
            
            if cursor.fetchone():
                if self.verbose:
                    print(f"    [INFO] Asset {asset_value} already being monitored")
                conn.close()
                return True
            
            # Add new asset
            cursor.execute('''
                INSERT INTO monitored_assets (asset_type, asset_value, last_check, current_hash)
                VALUES (?, ?, ?, ?)
            ''', (asset_type, asset_value, datetime.now(), ''))
            
            conn.commit()
            conn.close()
            
            if self.verbose:
                print(f"    [+] Added {asset_type} {asset_value} to monitoring")
            
            return True
            
        except Exception as e:
            if self.verbose:
                print(f"    [ERROR] Failed to add asset: {str(e)}")
            return False
    
    def start_monitoring(self, check_interval: int = 300):
        """
        Start continuous monitoring
        
        Args:
            check_interval (int): Check interval in seconds (default: 5 minutes)
        """
        if self.monitoring_active:
            if self.verbose:
                print("    [INFO] Monitoring already active")
            return
        
        self.monitoring_active = True
        self.monitor_thread = threading.Thread(
            target=self._monitoring_loop,
            args=(check_interval,)
        )
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
        if self.verbose:
            print(f"    [+] Started continuous monitoring (interval: {check_interval}s)")
    
    def stop_monitoring(self):
        """Stop continuous monitoring"""
        self.monitoring_active = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=10)
        
        if self.verbose:
            print("    [+] Stopped continuous monitoring")
    
    def _monitoring_loop(self, check_interval: int):
        """Main monitoring loop"""
        while self.monitoring_active:
            try:
                # Check monitored assets
                self._check_asset_changes()
                
                # Update vulnerability feeds
                self._update_vulnerability_feeds()
                
                # Generate alerts
                self._generate_alerts()
                
                time.sleep(check_interval)
                
            except Exception as e:
                if self.verbose:
                    print(f"    [ERROR] Monitoring loop error: {str(e)}")
                time.sleep(60)  # Wait 1 minute before retrying
    
    def _check_asset_changes(self):
        """Check for changes in monitored assets"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM monitored_assets WHERE status = "active"')
        assets = cursor.fetchall()
        
        for asset in assets:
            asset_id, asset_type, asset_value, last_check, current_hash, status, created_at = asset
            
            try:
                new_hash = self._get_asset_hash(asset_type, asset_value)
                
                if new_hash and new_hash != current_hash:
                    # Asset changed - record the change
                    cursor.execute('''
                        INSERT INTO asset_changes (asset_id, change_type, old_value, new_value)
                        VALUES (?, ?, ?, ?)
                    ''', (asset_id, 'hash_change', current_hash, new_hash))
                    
                    # Update asset record
                    cursor.execute('''
                        UPDATE monitored_assets 
                        SET current_hash = ?, last_check = ?
                        WHERE id = ?
                    ''', (new_hash, datetime.now(), asset_id))
                    
                    # Create alert
                    self._create_alert(
                        'asset_change',
                        'Medium',
                        f'{asset_type.title()} Change Detected',
                        f'Changes detected in {asset_type} {asset_value}',
                        asset_id=asset_id
                    )
                    
                    if self.verbose:
                        print(f"    [ALERT] Change detected in {asset_type} {asset_value}")
                
                else:
                    # No change - just update last check time
                    cursor.execute('''
                        UPDATE monitored_assets 
                        SET last_check = ?
                        WHERE id = ?
                    ''', (datetime.now(), asset_id))
                
            except Exception as e:
                if self.verbose:
                    print(f"    [ERROR] Failed to check {asset_type} {asset_value}: {str(e)}")
        
        conn.commit()
        conn.close()
    
    def _get_asset_hash(self, asset_type: str, asset_value: str) -> Optional[str]:
        """Get hash of current asset state"""
        try:
            if asset_type == 'domain':
                return self._get_domain_hash(asset_value)
            elif asset_type == 'ip':
                return self._get_ip_hash(asset_value)
            elif asset_type == 'service':
                return self._get_service_hash(asset_value)
            else:
                return None
                
        except Exception as e:
            if self.verbose:
                print(f"    [ERROR] Failed to get hash for {asset_type} {asset_value}: {str(e)}")
            return None
    
    def _get_domain_hash(self, domain: str) -> str:
        """Get hash representing current domain state"""
        try:
            import socket
            
            # Get IP addresses
            ips = []
            try:
                ip_info = socket.getaddrinfo(domain, None)
                ips = sorted(list(set([ip[4][0] for ip in ip_info])))
            except:
                pass
            
            # Get WHOIS info (simplified)
            whois_data = ""
            try:
                import whois
                w = whois.whois(domain)
                whois_data = str(w.creation_date) + str(w.expiration_date) + str(w.registrar)
            except:
                pass
            
            # Create hash from combined data
            combined_data = json.dumps({
                'ips': ips,
                'whois': whois_data
            }, sort_keys=True)
            
            return hashlib.sha256(combined_data.encode()).hexdigest()
            
        except Exception as e:
            return hashlib.sha256(domain.encode()).hexdigest()
    
    def _get_ip_hash(self, ip: str) -> str:
        """Get hash representing current IP state"""
        try:
            import socket
            
            # Try reverse DNS
            hostname = ""
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except:
                pass
            
            # Basic port scan of common ports
            open_ports = []
            common_ports = [21, 22, 23, 25, 53, 80, 110, 443, 993, 995]
            
            for port in common_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((ip, port))
                    if result == 0:
                        open_ports.append(port)
                    sock.close()
                except:
                    pass
            
            combined_data = json.dumps({
                'hostname': hostname,
                'open_ports': sorted(open_ports)
            }, sort_keys=True)
            
            return hashlib.sha256(combined_data.encode()).hexdigest()
            
        except Exception as e:
            return hashlib.sha256(ip.encode()).hexdigest()
    
    def _get_service_hash(self, service_url: str) -> str:
        """Get hash representing current service state"""
        try:
            response = requests.get(service_url, timeout=10, verify=False)
            
            service_data = {
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'content_length': len(response.content)
            }
            
            combined_data = json.dumps(service_data, sort_keys=True)
            return hashlib.sha256(combined_data.encode()).hexdigest()
            
        except Exception as e:
            return hashlib.sha256(service_url.encode()).hexdigest()
    
    def _update_vulnerability_feeds(self):
        """Update vulnerability feeds from external sources"""
        try:
            # Update CISA KEV feed
            self._update_cisa_kev_feed()
            
            # Update NVD feed (recent CVEs only due to rate limits)
            self._update_nvd_feed()
            
        except Exception as e:
            if self.verbose:
                print(f"    [ERROR] Failed to update vulnerability feeds: {str(e)}")
    
    def _update_cisa_kev_feed(self):
        """Update CISA Known Exploited Vulnerabilities feed"""
        try:
            response = requests.get(self.vulnerability_feeds['cisa_kev'], timeout=30)
            if response.status_code == 200:
                data = response.json()
                
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                for vuln in data.get('vulnerabilities', []):
                    cve_id = vuln.get('cveID')
                    if not cve_id:
                        continue
                    
                    # Check if already exists
                    cursor.execute('SELECT id FROM vulnerability_feed WHERE cve_id = ?', (cve_id,))
                    if cursor.fetchone():
                        continue
                    
                    cursor.execute('''
                        INSERT INTO vulnerability_feed 
                        (cve_id, title, description, severity, exploit_available, published_date, affected_products)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        cve_id,
                        vuln.get('vulnerabilityName', ''),
                        vuln.get('shortDescription', ''),
                        'High',  # CISA KEV are high priority
                        True,    # Known exploited
                        vuln.get('dateAdded'),
                        vuln.get('product', '')
                    ))
                
                conn.commit()
                conn.close()
                
                if self.verbose:
                    print("    [+] Updated CISA KEV feed")
                    
        except Exception as e:
            if self.verbose:
                print(f"    [ERROR] Failed to update CISA KEV feed: {str(e)}")
    
    def _update_nvd_feed(self):
        """Update NVD feed with recent CVEs"""
        try:
            # Get CVEs from last 7 days
            end_date = datetime.now()
            start_date = end_date - timedelta(days=7)
            
            params = {
                'pubStartDate': start_date.strftime('%Y-%m-%dT%H:%M:%S.000'),
                'pubEndDate': end_date.strftime('%Y-%m-%dT%H:%M:%S.000'),
                'resultsPerPage': 50
            }
            
            response = requests.get(self.vulnerability_feeds['nvd'], params=params, timeout=30)
            if response.status_code == 200:
                data = response.json()
                
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                for vuln in data.get('vulnerabilities', []):
                    cve_data = vuln.get('cve', {})
                    cve_id = cve_data.get('id')
                    
                    if not cve_id:
                        continue
                    
                    # Check if already exists
                    cursor.execute('SELECT id FROM vulnerability_feed WHERE cve_id = ?', (cve_id,))
                    if cursor.fetchone():
                        continue
                    
                    # Extract CVSS score and severity
                    cvss_score = 0.0
                    severity = 'Unknown'
                    
                    metrics = cve_data.get('metrics', {})
                    if 'cvssMetricV31' in metrics:
                        cvss_data = metrics['cvssMetricV31'][0]['cvssData']
                        cvss_score = cvss_data.get('baseScore', 0.0)
                        severity = cvss_data.get('baseSeverity', 'Unknown')
                    elif 'cvssMetricV2' in metrics:
                        cvss_data = metrics['cvssMetricV2'][0]['cvssData']
                        cvss_score = cvss_data.get('baseScore', 0.0)
                    
                    descriptions = cve_data.get('descriptions', [])
                    description = descriptions[0].get('value', '') if descriptions else ''
                    
                    cursor.execute('''
                        INSERT INTO vulnerability_feed 
                        (cve_id, description, severity, cvss_score, published_date)
                        VALUES (?, ?, ?, ?, ?)
                    ''', (
                        cve_id,
                        description,
                        severity,
                        cvss_score,
                        cve_data.get('published')
                    ))
                
                conn.commit()
                conn.close()
                
                if self.verbose:
                    print("    [+] Updated NVD feed")
                    
        except Exception as e:
            if self.verbose:
                print(f"    [ERROR] Failed to update NVD feed: {str(e)}")
    
    def _generate_alerts(self):
        """Generate alerts based on new vulnerabilities and asset changes"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Find high-severity vulnerabilities from last 24 hours
            cursor.execute('''
                SELECT * FROM vulnerability_feed 
                WHERE (severity = 'HIGH' OR severity = 'CRITICAL' OR cvss_score >= 7.0)
                AND created_at > datetime('now', '-1 day')
                AND cve_id NOT IN (SELECT cve_id FROM alerts WHERE cve_id IS NOT NULL)
            ''')
            
            new_vulns = cursor.fetchall()
            
            for vuln in new_vulns:
                self._create_alert(
                    'new_vulnerability',
                    vuln[4],  # severity
                    f'New High-Severity Vulnerability: {vuln[1]}',
                    f'CVE: {vuln[1]} - {vuln[3][:200]}...' if len(vuln[3]) > 200 else vuln[3],
                    cve_id=vuln[1]
                )
            
            conn.close()
            
        except Exception as e:
            if self.verbose:
                print(f"    [ERROR] Failed to generate alerts: {str(e)}")
    
    def _create_alert(self, alert_type: str, severity: str, title: str, 
                     description: str, asset_id: int = None, cve_id: str = None):
        """Create a new alert"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO alerts (alert_type, severity, title, description, asset_id, cve_id)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (alert_type, severity, title, description, asset_id, cve_id))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            if self.verbose:
                print(f"    [ERROR] Failed to create alert: {str(e)}")
    
    def get_alerts(self, status: str = 'new', limit: int = 50) -> List[Dict]:
        """
        Get alerts from the database
        
        Args:
            status (str): Alert status filter
            limit (int): Maximum number of alerts to return
            
        Returns:
            List[Dict]: List of alerts
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM alerts 
                WHERE status = ? 
                ORDER BY created_at DESC 
                LIMIT ?
            ''', (status, limit))
            
            alerts = []
            for row in cursor.fetchall():
                alerts.append({
                    'id': row[0],
                    'alert_type': row[1],
                    'severity': row[2],
                    'title': row[3],
                    'description': row[4],
                    'asset_id': row[5],
                    'cve_id': row[6],
                    'status': row[7],
                    'created_at': row[8]
                })
            
            conn.close()
            return alerts
            
        except Exception as e:
            if self.verbose:
                print(f"    [ERROR] Failed to get alerts: {str(e)}")
            return []
    
    def get_monitoring_stats(self) -> Dict:
        """Get monitoring statistics"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get asset counts
            cursor.execute('SELECT COUNT(*) FROM monitored_assets WHERE status = "active"')
            active_assets = cursor.fetchone()[0]
            
            # Get alert counts
            cursor.execute('SELECT COUNT(*) FROM alerts WHERE status = "new"')
            new_alerts = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM alerts WHERE created_at > datetime("now", "-24 hours")')
            alerts_24h = cursor.fetchone()[0]
            
            # Get vulnerability counts
            cursor.execute('SELECT COUNT(*) FROM vulnerability_feed WHERE created_at > datetime("now", "-7 days")')
            new_vulns_7d = cursor.fetchone()[0]
            
            # Get recent changes
            cursor.execute('''
                SELECT COUNT(*) FROM asset_changes 
                WHERE detected_at > datetime("now", "-24 hours")
            ''')
            changes_24h = cursor.fetchone()[0]
            
            conn.close()
            
            return {
                'monitoring_active': self.monitoring_active,
                'active_assets': active_assets,
                'new_alerts': new_alerts,
                'alerts_24h': alerts_24h,
                'new_vulnerabilities_7d': new_vulns_7d,
                'asset_changes_24h': changes_24h,
                'last_update': datetime.now().isoformat()
            }
            
        except Exception as e:
            if self.verbose:
                print(f"    [ERROR] Failed to get monitoring stats: {str(e)}")
            return {}
    
    def mark_alert_read(self, alert_id: int) -> bool:
        """Mark an alert as read"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute(
                'UPDATE alerts SET status = "read" WHERE id = ?',
                (alert_id,)
            )
            
            conn.commit()
            conn.close()
            return True
            
        except Exception as e:
            if self.verbose:
                print(f"    [ERROR] Failed to mark alert as read: {str(e)}")
            return False
