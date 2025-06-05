"""
Report Generator Module
Handles generation of comprehensive reports in multiple formats (text, JSON, HTML)
"""

import json
import datetime
import os
from jinja2 import Template

class ReportGenerator:
    def __init__(self, verbose=False):
        """
        Initialize report generator
        
        Args:
            verbose (bool): Enable verbose output
        """
        self.verbose = verbose
    
    def generate_text_report(self, results, output_file=None):
        """
        Generate text format report
        
        Args:
            results (dict): Scan results
            output_file (str): Output file path (optional)
        """
        report_content = self._generate_text_content(results)
        
        if output_file:
            try:
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(report_content)
                if self.verbose:
                    print(f"[INFO] Text report saved to {output_file}")
            except Exception as e:
                print(f"[ERROR] Failed to save text report: {str(e)}")
        
        return report_content
    
    def generate_json_report(self, results, output_file=None):
        """
        Generate JSON format report
        
        Args:
            results (dict): Scan results
            output_file (str): Output file path (optional)
        """
        # Add metadata to results
        enhanced_results = {
            'report_metadata': {
                'generated_at': datetime.datetime.now().isoformat(),
                'tool_name': 'InfoGather',
                'tool_version': '1.0',
                'report_format': 'JSON'
            },
            'scan_results': results
        }
        
        if output_file:
            try:
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(enhanced_results, f, indent=2, default=str)
                if self.verbose:
                    print(f"[INFO] JSON report saved to {output_file}")
            except Exception as e:
                print(f"[ERROR] Failed to save JSON report: {str(e)}")
        
        return enhanced_results
    
    def generate_html_report(self, results, output_file=None):
        """
        Generate HTML format report
        
        Args:
            results (dict): Scan results
            output_file (str): Output file path (optional)
        """
        html_content = self._generate_html_content(results)
        
        if output_file:
            try:
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(html_content)
                if self.verbose:
                    print(f"[INFO] HTML report saved to {output_file}")
            except Exception as e:
                print(f"[ERROR] Failed to save HTML report: {str(e)}")
        
        return html_content
    
    def display_console_report(self, results):
        """
        Display formatted report to console
        
        Args:
            results (dict): Scan results
        """
        print(self._generate_text_content(results))
    
    def _generate_text_content(self, results):
        """Generate text report content"""
        content = []
        content.append("=" * 80)
        content.append("InfoGather - Penetration Testing Report")
        content.append("=" * 80)
        content.append(f"Report Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        content.append(f"Scan Time: {results.get('scan_time', 'Unknown')}")
        content.append(f"Target(s): {', '.join(results.get('targets', []))}")
        content.append("")
        
        # Executive Summary
        content.append("EXECUTIVE SUMMARY")
        content.append("-" * 40)
        total_targets = len(results.get('targets', []))
        total_issues = 0
        critical_issues = 0
        high_issues = 0
        
        # Count issues across all targets
        for target, target_results in results.get('results', {}).items():
            if 'vuln_scan' in target_results:
                vuln_summary = target_results['vuln_scan'].get('summary', {})
                total_issues += vuln_summary.get('total_vulnerabilities', 0)
                critical_issues += vuln_summary.get('critical', 0)
                high_issues += vuln_summary.get('high', 0)
        
        content.append(f"Targets Scanned: {total_targets}")
        content.append(f"Total Issues Found: {total_issues}")
        content.append(f"Critical Issues: {critical_issues}")
        content.append(f"High Risk Issues: {high_issues}")
        content.append("")
        
        # Detailed Results for each target
        for target, target_results in results.get('results', {}).items():
            content.append(f"TARGET: {target}")
            content.append("=" * 60)
            
            # Network Scan Results
            if 'network_scan' in target_results:
                content.extend(self._format_network_scan(target_results['network_scan']))
            
            # DNS Enumeration Results
            if 'dns_enum' in target_results:
                content.extend(self._format_dns_enum(target_results['dns_enum']))
            
            # WHOIS Results
            if 'whois' in target_results:
                content.extend(self._format_whois(target_results['whois']))
            
            # SSL Analysis Results
            if 'ssl_analysis' in target_results:
                content.extend(self._format_ssl_analysis(target_results['ssl_analysis']))
            
            # Vulnerability Scan Results
            if 'vuln_scan' in target_results:
                content.extend(self._format_vuln_scan(target_results['vuln_scan']))
            
            content.append("")
        
        # Recommendations
        content.append("RECOMMENDATIONS")
        content.append("-" * 40)
        recommendations = self._generate_recommendations(results)
        for rec in recommendations:
            content.append(f"• {rec}")
        content.append("")
        
        content.append("=" * 80)
        content.append("End of Report")
        content.append("=" * 80)
        
        return "\n".join(content)
    
    def _format_network_scan(self, network_scan):
        """Format network scan results for text output"""
        content = []
        content.append("Network Scan Results:")
        content.append("-" * 30)
        
        if 'host_discovery' in network_scan:
            host_disc = network_scan['host_discovery']
            content.append(f"Host Status: {'UP' if host_disc.get('is_up') else 'DOWN'}")
            if host_disc.get('response_time'):
                content.append(f"Response Time: {host_disc['response_time']}s")
        
        if 'port_scan' in network_scan and 'summary' in network_scan['port_scan']:
            summary = network_scan['port_scan']['summary']
            content.append(f"Ports Scanned: {summary.get('total', 0)}")
            content.append(f"Open Ports: {summary.get('open', 0)}")
            content.append(f"Closed Ports: {summary.get('closed', 0)}")
            content.append(f"Filtered Ports: {summary.get('filtered', 0)}")
            
            # List open ports
            if 'ports' in network_scan['port_scan']:
                open_ports = [str(port) for port, info in network_scan['port_scan']['ports'].items() 
                             if info.get('state') == 'open']
                if open_ports:
                    content.append(f"Open Ports: {', '.join(open_ports)}")
        
        if 'service_detection' in network_scan and 'services' in network_scan['service_detection']:
            content.append("Services Detected:")
            for port, service in network_scan['service_detection']['services'].items():
                service_name = service.get('name', 'unknown')
                product = service.get('product', '')
                version = service.get('version', '')
                service_str = f"  Port {port}: {service_name}"
                if product:
                    service_str += f" ({product}"
                    if version:
                        service_str += f" {version}"
                    service_str += ")"
                content.append(service_str)
        
        content.append("")
        return content
    
    def _format_dns_enum(self, dns_enum):
        """Format DNS enumeration results for text output"""
        content = []
        content.append("DNS Enumeration Results:")
        content.append("-" * 30)
        
        if 'dns_records' in dns_enum:
            for record_type, records in dns_enum['dns_records'].items():
                if records:
                    content.append(f"{record_type} Records:")
                    for record in records[:5]:  # Limit to first 5 records
                        if isinstance(record, dict):
                            content.append(f"  {record}")
                        else:
                            content.append(f"  {record}")
        
        if 'subdomains' in dns_enum and dns_enum['subdomains']:
            content.append(f"Subdomains Found ({len(dns_enum['subdomains'])}):")
            for subdomain in dns_enum['subdomains'][:10]:  # Limit to first 10
                subdomain_name = subdomain.get('subdomain', str(subdomain))
                content.append(f"  {subdomain_name}")
            if len(dns_enum['subdomains']) > 10:
                content.append(f"  ... and {len(dns_enum['subdomains']) - 10} more")
        
        if 'zone_transfer' in dns_enum:
            zt = dns_enum['zone_transfer']
            if zt.get('attempted'):
                if zt.get('successful'):
                    content.append(f"Zone Transfer: SUCCESSFUL ({len(zt.get('records', []))} records)")
                else:
                    content.append("Zone Transfer: Failed (properly configured)")
        
        content.append("")
        return content
    
    def _format_whois(self, whois_data):
        """Format WHOIS results for text output"""
        content = []
        content.append("WHOIS Information:")
        content.append("-" * 30)
        
        if 'domain_whois' in whois_data:
            domain_info = whois_data['domain_whois']
            if 'registrar' in domain_info and domain_info['registrar']:
                content.append(f"Registrar: {domain_info['registrar']}")
            if 'creation_date' in domain_info and domain_info['creation_date']:
                content.append(f"Created: {domain_info['creation_date']}")
            if 'expiration_date' in domain_info and domain_info['expiration_date']:
                content.append(f"Expires: {domain_info['expiration_date']}")
            if 'domain_age_days' in domain_info:
                content.append(f"Domain Age: {domain_info['domain_age_days']} days")
        
        if 'ip_whois' in whois_data:
            ip_info = whois_data['ip_whois']
            if 'organization' in ip_info and ip_info['organization']:
                content.append(f"Organization: {ip_info['organization']}")
            if 'country' in ip_info and ip_info['country']:
                content.append(f"Country: {ip_info['country']}")
            if 'isp' in ip_info and ip_info['isp']:
                content.append(f"ISP: {ip_info['isp']}")
        
        content.append("")
        return content
    
    def _format_ssl_analysis(self, ssl_analysis):
        """Format SSL analysis results for text output"""
        content = []
        content.append("SSL/TLS Analysis:")
        content.append("-" * 30)
        
        ssl_services = ssl_analysis.get('ssl_services', {})
        ssl_count = sum(1 for service in ssl_services.values() if service.get('ssl_enabled'))
        content.append(f"SSL Services Found: {ssl_count}")
        
        for port, service in ssl_services.items():
            if service.get('ssl_enabled'):
                content.append(f"  Port {port}: {service.get('ssl_version', 'Unknown')} "
                             f"({service.get('cipher_suite', ['Unknown'])[0] if service.get('cipher_suite') else 'Unknown'})")
        
        # Certificate information
        for port, cert_info in ssl_analysis.get('certificates', {}).items():
            if 'certificate_details' in cert_info:
                cert_details = cert_info['certificate_details']
                content.append(f"Certificate (Port {port}):")
                if 'subject' in cert_details and 'commonName' in cert_details['subject']:
                    content.append(f"  Subject: {cert_details['subject']['commonName']}")
                if 'issuer' in cert_details and 'commonName' in cert_details['issuer']:
                    content.append(f"  Issuer: {cert_details['issuer']['commonName']}")
                if 'days_until_expiry' in cert_details:
                    days = cert_details['days_until_expiry']
                    status = "EXPIRED" if days < 0 else f"{days} days"
                    content.append(f"  Expires: {status}")
        
        # Security assessment
        if 'security_assessment' in ssl_analysis:
            assessment = ssl_analysis['security_assessment']
            content.append(f"Security Score: {assessment.get('overall_score', 'Unknown')}/100 "
                         f"({assessment.get('security_level', 'Unknown')})")
        
        # Vulnerabilities
        vulnerabilities = ssl_analysis.get('vulnerabilities', [])
        if vulnerabilities:
            content.append(f"SSL Vulnerabilities ({len(vulnerabilities)}):")
            for vuln in vulnerabilities[:5]:  # Limit to first 5
                content.append(f"  • {vuln.get('vulnerability', 'Unknown')} "
                             f"({vuln.get('severity', 'Unknown')})")
        
        content.append("")
        return content
    
    def _format_vuln_scan(self, vuln_scan):
        """Format vulnerability scan results for text output"""
        content = []
        content.append("Vulnerability Scan Results:")
        content.append("-" * 30)
        
        if 'summary' in vuln_scan:
            summary = vuln_scan['summary']
            content.append(f"Total Vulnerabilities: {summary.get('total_vulnerabilities', 0)}")
            content.append(f"Critical: {summary.get('critical', 0)}")
            content.append(f"High: {summary.get('high', 0)}")
            content.append(f"Medium: {summary.get('medium', 0)}")
            content.append(f"Low: {summary.get('low', 0)}")
        
        # Service vulnerabilities
        service_vulns = vuln_scan.get('service_vulnerabilities', {})
        if service_vulns:
            content.append("Service Vulnerabilities:")
            for port, vulns in service_vulns.items():
                content.append(f"  Port {port}:")
                for vuln in vulns:
                    content.append(f"    • {vuln.get('vulnerability', 'Unknown')} "
                                 f"({vuln.get('severity', 'Unknown')})")
        
        # Web vulnerabilities
        web_vulns = vuln_scan.get('web_vulnerabilities', {})
        if web_vulns:
            content.append("Web Vulnerabilities:")
            for port, vulns in web_vulns.items():
                content.append(f"  Port {port}:")
                for vuln in vulns:
                    content.append(f"    • {vuln.get('vulnerability', 'Unknown')} "
                                 f"({vuln.get('severity', 'Unknown')})")
        
        # Network vulnerabilities
        network_vulns = vuln_scan.get('network_vulnerabilities', [])
        if network_vulns:
            content.append("Network Vulnerabilities:")
            for vuln in network_vulns:
                content.append(f"  • {vuln.get('vulnerability', 'Unknown')} "
                             f"({vuln.get('severity', 'Unknown')})")
        
        content.append("")
        return content
    
    def _generate_html_content(self, results):
        """Generate HTML report content"""
        # HTML template
        html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>InfoGather - Penetration Testing Report</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .header {
            text-align: center;
            border-bottom: 3px solid #007acc;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }
        .header h1 {
            color: #007acc;
            margin: 0;
            font-size: 2.5em;
        }
        .header p {
            color: #666;
            margin: 10px 0 0 0;
            font-size: 1.1em;
        }
        .summary {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 30px;
            border-left: 4px solid #007acc;
        }
        .summary h2 {
            margin-top: 0;
            color: #007acc;
        }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }
        .stat-box {
            background: white;
            padding: 15px;
            border-radius: 5px;
            text-align: center;
            border: 1px solid #ddd;
        }
        .stat-number {
            font-size: 2em;
            font-weight: bold;
            color: #007acc;
        }
        .stat-label {
            color: #666;
            font-size: 0.9em;
        }
        .target-section {
            margin-bottom: 40px;
            border: 1px solid #ddd;
            border-radius: 5px;
            overflow: hidden;
        }
        .target-header {
            background: #007acc;
            color: white;
            padding: 15px 20px;
            font-size: 1.3em;
            font-weight: bold;
        }
        .target-content {
            padding: 20px;
        }
        .module-section {
            margin-bottom: 25px;
        }
        .module-title {
            color: #333;
            border-bottom: 2px solid #eee;
            padding-bottom: 5px;
            margin-bottom: 15px;
        }
        .vulnerability {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            border-radius: 4px;
            padding: 10px;
            margin-bottom: 10px;
        }
        .vulnerability.critical {
            background: #f8d7da;
            border-color: #f5c6cb;
        }
        .vulnerability.high {
            background: #ffeeba;
            border-color: #ffeaa7;
        }
        .vulnerability.medium {
            background: #d1ecf1;
            border-color: #bee5eb;
        }
        .vulnerability.low {
            background: #d4edda;
            border-color: #c3e6cb;
        }
        .severity {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 3px;
            font-size: 0.8em;
            font-weight: bold;
            text-transform: uppercase;
        }
        .severity.critical { background: #dc3545; color: white; }
        .severity.high { background: #fd7e14; color: white; }
        .severity.medium { background: #ffc107; color: black; }
        .severity.low { background: #28a745; color: white; }
        .table {
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }
        .table th, .table td {
            border: 1px solid #ddd;
            padding: 8px 12px;
            text-align: left;
        }
        .table th {
            background: #f8f9fa;
            font-weight: bold;
        }
        .footer {
            text-align: center;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            color: #666;
        }
        .recommendations {
            background: #e7f3ff;
            padding: 20px;
            border-radius: 5px;
            border-left: 4px solid #007acc;
            margin: 30px 0;
        }
        .recommendations h2 {
            margin-top: 0;
            color: #007acc;
        }
        .recommendations ul {
            margin: 0;
            padding-left: 20px;
        }
        .recommendations li {
            margin-bottom: 5px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>InfoGather</h1>
            <p>Penetration Testing Report</p>
            <p>Generated: {{ generated_time }}</p>
        </div>

        <div class="summary">
            <h2>Executive Summary</h2>
            <div class="stats">
                <div class="stat-box">
                    <div class="stat-number">{{ total_targets }}</div>
                    <div class="stat-label">Targets Scanned</div>
                </div>
                <div class="stat-box">
                    <div class="stat-number">{{ total_issues }}</div>
                    <div class="stat-label">Total Issues</div>
                </div>
                <div class="stat-box">
                    <div class="stat-number">{{ critical_issues }}</div>
                    <div class="stat-label">Critical</div>
                </div>
                <div class="stat-box">
                    <div class="stat-number">{{ high_issues }}</div>
                    <div class="stat-label">High Risk</div>
                </div>
            </div>
        </div>

        {% for target, target_data in target_results.items() %}
        <div class="target-section">
            <div class="target-header">Target: {{ target }}</div>
            <div class="target-content">
                
                {% if target_data.network_scan %}
                <div class="module-section">
                    <h3 class="module-title">Network Scan Results</h3>
                    {{ format_network_scan(target_data.network_scan) }}
                </div>
                {% endif %}

                {% if target_data.dns_enum %}
                <div class="module-section">
                    <h3 class="module-title">DNS Enumeration</h3>
                    {{ format_dns_enum(target_data.dns_enum) }}
                </div>
                {% endif %}

                {% if target_data.whois %}
                <div class="module-section">
                    <h3 class="module-title">WHOIS Information</h3>
                    {{ format_whois(target_data.whois) }}
                </div>
                {% endif %}

                {% if target_data.ssl_analysis %}
                <div class="module-section">
                    <h3 class="module-title">SSL/TLS Analysis</h3>
                    {{ format_ssl_analysis(target_data.ssl_analysis) }}
                </div>
                {% endif %}

                {% if target_data.vuln_scan %}
                <div class="module-section">
                    <h3 class="module-title">Vulnerability Scan</h3>
                    {{ format_vuln_scan(target_data.vuln_scan) }}
                </div>
                {% endif %}

            </div>
        </div>
        {% endfor %}

        <div class="recommendations">
            <h2>Recommendations</h2>
            <ul>
                {% for rec in recommendations %}
                <li>{{ rec }}</li>
                {% endfor %}
            </ul>
        </div>

        <div class="footer">
            <p>Report generated by InfoGather v1.0 - For authorized security testing only</p>
        </div>
    </div>
</body>
</html>
        """
        
        # Prepare template data
        template_data = {
            'generated_time': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'total_targets': len(results.get('targets', [])),
            'target_results': results.get('results', {}),
            'recommendations': self._generate_recommendations(results)
        }
        
        # Calculate summary statistics
        total_issues = 0
        critical_issues = 0
        high_issues = 0
        
        for target_results in results.get('results', {}).values():
            if 'vuln_scan' in target_results:
                vuln_summary = target_results['vuln_scan'].get('summary', {})
                total_issues += vuln_summary.get('total_vulnerabilities', 0)
                critical_issues += vuln_summary.get('critical', 0)
                high_issues += vuln_summary.get('high', 0)
        
        template_data.update({
            'total_issues': total_issues,
            'critical_issues': critical_issues,
            'high_issues': high_issues
        })
        
        # Use simple string formatting instead of Jinja2 for basic templating
        html_content = html_template
        for key, value in template_data.items():
            if isinstance(value, (str, int)):
                html_content = html_content.replace(f'{{{{ {key} }}}}', str(value))
        
        # Remove Jinja2 syntax that we can't easily replace
        html_content = re.sub(r'\{\%.*?\%\}', '', html_content, flags=re.DOTALL)
        html_content = re.sub(r'\{\{.*?\}\}', '', html_content)
        
        return html_content
    
    def _generate_recommendations(self, results):
        """Generate security recommendations based on scan results"""
        recommendations = []
        
        # Analyze results to generate specific recommendations
        has_critical = False
        has_high = False
        has_ssl_issues = False
        has_weak_services = False
        has_info_disclosure = False
        
        for target_results in results.get('results', {}).values():
            # Check vulnerability summary
            if 'vuln_scan' in target_results:
                vuln_summary = target_results['vuln_scan'].get('summary', {})
                if vuln_summary.get('critical', 0) > 0:
                    has_critical = True
                if vuln_summary.get('high', 0) > 0:
                    has_high = True
            
            # Check SSL issues
            if 'ssl_analysis' in target_results:
                ssl_vulns = target_results['ssl_analysis'].get('vulnerabilities', [])
                if ssl_vulns:
                    has_ssl_issues = True
            
            # Check for weak services
            if 'network_scan' in target_results and 'service_detection' in target_results['network_scan']:
                services = target_results['network_scan']['service_detection'].get('services', {})
                weak_services = ['telnet', 'ftp', 'tftp', 'rsh', 'rlogin']
                for service_info in services.values():
                    if any(weak in service_info.get('name', '').lower() for weak in weak_services):
                        has_weak_services = True
            
            # Check for information disclosure
            if 'vuln_scan' in target_results and 'information_disclosure' in target_results['vuln_scan']:
                if target_results['vuln_scan']['information_disclosure'].get('banners'):
                    has_info_disclosure = True
        
        # Generate specific recommendations
        if has_critical:
            recommendations.append("Immediately address all critical vulnerabilities as they pose severe security risks")
        
        if has_high:
            recommendations.append("Prioritize remediation of high-severity vulnerabilities within 24-48 hours")
        
        if has_ssl_issues:
            recommendations.append("Update SSL/TLS configuration to use strong ciphers and protocols (TLS 1.2+)")
        
        if has_weak_services:
            recommendations.append("Replace insecure services (Telnet, FTP, etc.) with secure alternatives (SSH, SFTP)")
        
        if has_info_disclosure:
            recommendations.append("Configure services to minimize information disclosure in banners and headers")
        
        # General recommendations
        recommendations.extend([
            "Implement regular vulnerability scanning and security assessments",
            "Keep all systems and software updated with latest security patches",
            "Use strong authentication mechanisms and access controls",
            "Monitor network traffic and system logs for suspicious activities",
            "Implement proper firewall rules and network segmentation",
            "Regular security awareness training for staff",
            "Develop and test incident response procedures"
        ])
        
        return recommendations[:10]  # Limit to top 10 recommendations
    
    def generate_executive_summary(self, results):
        """Generate executive summary for management reporting"""
        summary = {
            'assessment_overview': {
                'targets_scanned': len(results.get('targets', [])),
                'scan_date': results.get('scan_time', 'Unknown'),
                'total_findings': 0,
                'risk_level': 'Unknown'
            },
            'risk_breakdown': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0
            },
            'key_findings': [],
            'immediate_actions': [],
            'business_impact': ''
        }
        
        # Calculate risk statistics
        total_critical = 0
        total_high = 0
        total_medium = 0
        total_low = 0
        
        for target_results in results.get('results', {}).values():
            if 'vuln_scan' in target_results:
                vuln_summary = target_results['vuln_scan'].get('summary', {})
                total_critical += vuln_summary.get('critical', 0)
                total_high += vuln_summary.get('high', 0)
                total_medium += vuln_summary.get('medium', 0)
                total_low += vuln_summary.get('low', 0)
        
        summary['risk_breakdown'] = {
            'critical': total_critical,
            'high': total_high,
            'medium': total_medium,
            'low': total_low
        }
        
        summary['assessment_overview']['total_findings'] = total_critical + total_high + total_medium + total_low
        
        # Determine overall risk level
        if total_critical > 0:
            summary['assessment_overview']['risk_level'] = 'Critical'
            summary['business_impact'] = 'Immediate action required. Critical vulnerabilities could lead to complete system compromise.'
        elif total_high > 0:
            summary['assessment_overview']['risk_level'] = 'High'
            summary['business_impact'] = 'High risk of security breach. Prompt remediation recommended.'
        elif total_medium > 0:
            summary['assessment_overview']['risk_level'] = 'Medium'
            summary['business_impact'] = 'Moderate security risk. Address vulnerabilities in next maintenance window.'
        elif total_low > 0:
            summary['assessment_overview']['risk_level'] = 'Low'
            summary['business_impact'] = 'Low security risk. Monitor and address during regular updates.'
        else:
            summary['assessment_overview']['risk_level'] = 'Minimal'
            summary['business_impact'] = 'No significant security issues identified.'
        
        return summary
