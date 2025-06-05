# InfoGather - Penetration Testing Information Gathering Tool

InfoGather is a comprehensive Python-based information gathering tool designed for authorized security assessments and penetration testing. This tool provides network discovery, vulnerability scanning, DNS enumeration, SSL analysis, and detailed reporting capabilities.

## ⚠️ **DISCLAIMER**

**FOR AUTHORIZED SECURITY TESTING ONLY**

This tool is intended for legitimate security testing and assessment purposes only. Ensure you have explicit written permission before using this tool on any network or system you do not own. Unauthorized use may violate laws and regulations.

## 🚀 Features

### Core Capabilities
- **Network Discovery & Host Enumeration**: Identify live hosts and open ports
- **Port Scanning**: Comprehensive TCP/UDP port scanning with service detection
- **Service Detection**: Version identification and banner grabbing
- **DNS Enumeration**: Subdomain discovery, zone transfer testing, DNS record analysis
- **WHOIS Information Gathering**: Domain and IP registration details
- **SSL/TLS Certificate Analysis**: Certificate validation, vulnerability assessment
- **Vulnerability Scanning**: Basic security vulnerability detection
- **Comprehensive Reporting**: Multiple output formats (text, JSON, HTML)

### Advanced Features
- **Parallel Processing**: Multi-threaded scanning for improved performance
- **Configurable Scan Intensity**: Timing templates for stealth or speed
- **Modular Design**: Easy to extend with additional modules
- **Progress Indicators**: Real-time feedback for long-running scans
- **Error Handling**: Robust error handling for network timeouts and failures

## 📋 Requirements

### Python Libraries
- `python-nmap`: Network scanning capabilities
- `requests`: HTTP-based reconnaissance
- `dnspython`: DNS operations and queries
- `python-whois`: Domain information gathering
- `cryptography`: SSL/TLS certificate analysis
- `jinja2`: HTML report templating (optional)

### System Requirements
- Python 3.7 or higher
- `nmap` binary installed on the system
- Network connectivity to target systems
- Appropriate permissions for network scanning

## 🛠️ Installation

1. **Clone the repository:**
```bash
git clone <repository_url>
cd infogather
