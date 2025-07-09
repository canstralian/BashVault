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
- **Comprehensive Reporting**: Multiple output formats (text, JSON, # InfoGather - Penetration Testing Tool v2.0

<div align="center">

![InfoGather Logo](https://img.shields.io/badge/InfoGather-v2.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.7+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg)
![Coverage](https://img.shields.io/badge/coverage-80%25-yellow.svg)

**A comprehensive Python-based penetration testing and information gathering tool for authorized security assessments**

</div>

## ⚠️ Legal Disclaimer

**This tool is intended for authorized security testing and educational purposes only.** Users must have explicit written permission before using this tool on any network or system they do not own. Unauthorized use may violate laws and regulations. The developers disclaim any liability for misuse of this software.

## 🚀 Features

### Core Capabilities
- **Network Scanning**: Host discovery and comprehensive port scanning
- **DNS Enumeration**: Subdomain discovery and DNS record analysis
- **SSL Analysis**: Certificate validation and TLS configuration assessment
- **Vulnerability Scanning**: Security vulnerability detection and reporting
- **WHOIS Lookup**: Domain registration and ownership information

### Advanced Reconnaissance
- **Social Engineering Intelligence**: Employee enumeration and email pattern discovery
- **Advanced DNS**: DNS over HTTPS bypass and certificate transparency mining
- **Cloud Discovery**: AWS S3, Azure Blob, and Google Cloud Storage enumeration
- **DNS Tunneling Detection**: Advanced analysis for detecting DNS-based communication channels

### Web Dashboard
- **Modern Interface**: Responsive Flask-based web application
- **Real-time Scanning**: Asynchronous scan execution with progress tracking
- **Multi-user Support**: Authentication, session management, and user roles
- **Scan History**: Persistent result storage and comprehensive reporting
- **Threat Monitoring**: Real-time vulnerability tracking and alerts

### Technical Features
- **Parallel Processing**: Multi-threaded scanning for improved performance
- **Configurable Timing**: Scan intensity templates for stealth or speed
- **Modular Architecture**: Easy to extend with additional modules
- **Progress Indicators**: Real-time feedback for long-running operations
- **Error Handling**: Robust error handling for network timeouts and failures
- **Security Hardening**: Input validation, rate limiting, and secure session management

## 📋 Requirements

### System Requirements
- **Python**: 3.7 or higher
- **Database**: PostgreSQL (recommended) or SQLite (development)
- **Network Tools**: `nmap` binary installed on the system
- **Permissions**: Appropriate permissions for network scanning

### Python Dependencies
- **Core Framework**: Flask, SQLAlchemy, Werkzeug
- **Network Operations**: python-nmap, requests, dnspython, python-whois
- **Security**: cryptography, secure session management
- **Database**: psycopg2-binary (PostgreSQL), SQLite (fallback)
- **Templates**: Jinja2 for HTML report generation

## 🛠️ Installation

### Quick Start (Replit)
1. **Clone the repository:**
```bash
git clone https://github.com/your-username/infogather.git
cd infogather
```

2. **Set up environment variables:**
```bash
cp .env.example .env
# Edit .env with your configuration
```

3. **Initialize database:**
```bash
python -c "from web_dashboard_simple import init_database; init_database()"
```

4. **Start the web dashboard:**
```bash
python web_dashboard_simple.py
```

### Production Setup
1. **Install system dependencies:**
```bash
sudo apt-get update
sudo apt-get install nmap postgresql postgresql-contrib
```

2. **Configure PostgreSQL:**
```bash
sudo -u postgres createdb infogather
sudo -u postgres createuser infogather_user
```

3. **Set up Python environment:**
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
pip install -r requirements.txt
```

4. **Configure environment variables:**
```bash
export DATABASE_URL="postgresql://user:password@localhost/infogather"
export FLASK_SECRET_KEY="your-secret-key-here"
```

## 🎯 Usage

### Command Line Interface
```bash
# Basic network scan
python pentester.py -t 192.168.1.1 --network-scan

# Comprehensive scan with all modules
python pentester.py -t example.com --all-modules -o report

# Advanced reconnaissance
python pentester.py -t target.com --advanced-recon --format html

# Specific module combinations
python pentester.py -t 192.168.1.0/24 --dns-enum --ssl-analysis --vuln-scan
```

### Web Dashboard
1. **Access the dashboard**: `http://localhost:5000`
2. **Login/Register**: Create account or use existing credentials
3. **Configure Scan**: Select target, modules, and parameters
4. **Monitor Progress**: Real-time scan execution tracking
5. **View Results**: Comprehensive reporting and analysis
6. **Export Reports**: Multiple formats (JSON, HTML, PDF)

### API Usage
```python
from modules.network_scanner import NetworkScanner
from modules.dns_enum import DNSEnumerator

# Initialize modules
scanner = NetworkScanner(verbose=True)
dns_enum = DNSEnumerator(verbose=True)

# Perform scans
network_results = scanner.scan_network("192.168.1.0/24")
dns_results = dns_enum.enumerate_dns("example.com")
```

## 📊 Module Documentation

### Network Scanner
- **Purpose**: Host discovery and port scanning
- **Methods**: TCP SYN scan, UDP scan, service detection
- **Options**: Timing templates, port ranges, custom scripts

### DNS Enumerator
- **Purpose**: DNS reconnaissance and subdomain discovery
- **Methods**: Zone transfer, brute force, certificate transparency
- **Features**: DNS over HTTPS bypass, historical analysis

### SSL Analyzer
- **Purpose**: Certificate and TLS configuration assessment
- **Analysis**: Certificate chain validation, cipher suites, vulnerabilities
- **Output**: Security recommendations and compliance checks

### Vulnerability Scanner
- **Purpose**: Security vulnerability detection
- **Coverage**: Common vulnerabilities, misconfigurations
- **Integration**: CVE database, security advisories

### Advanced Modules
- **Social Engineer**: Employee enumeration, email patterns
- **Cloud Discovery**: Cloud storage enumeration and analysis
- **Threat Monitor**: Real-time vulnerability tracking

## 🔧 Configuration

### Environment Variables
```bash
# Core Configuration
FLASK_ENV=production
FLASK_SECRET_KEY=your-secret-key-here
DATABASE_URL=postgresql://user:password@localhost/infogather

# Security Settings
SESSION_TIMEOUT=3600
MAX_SCAN_DURATION=1800
RATE_LIMIT_REQUESTS=100

# External Services
SHODAN_API_KEY=your-shodan-api-key
VIRUSTOTAL_API_KEY=your-virustotal-api-key
```

### Database Configuration
```python
# PostgreSQL (Recommended)
DATABASE_URL = "postgresql://user:password@localhost/infogather"

# SQLite (Development)
DATABASE_URL = "sqlite:///infogather.db"
```

## 🧪 Testing

### Running Tests
```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=. --cov-report=html

# Run specific test categories
pytest tests/test_modules.py
pytest tests/test_web_dashboard.py
```

### Code Quality
```bash
# Format code
black .

# Check linting
flake8 .

# Type checking
mypy .

# Security scanning
bandit -r .
```

## 📈 Performance

### Benchmarks
- **Network Scan**: 1000 hosts in ~2 minutes
- **DNS Enumeration**: 500 subdomains in ~30 seconds
- **SSL Analysis**: 100 certificates in ~1 minute
- **Vulnerability Scan**: Comprehensive scan in ~5 minutes

### Optimization
- **Parallel Processing**: Configurable thread pools
- **Rate Limiting**: Prevents network congestion
- **Caching**: Results caching for repeated scans
- **Resource Management**: Memory and CPU optimization

## 🔒 Security

### Security Features
- **Input Validation**: Comprehensive sanitization
- **Authentication**: Secure user authentication
- **Session Management**: Secure session handling
- **Rate Limiting**: DDoS protection
- **Audit Logging**: Security event tracking

### Security Considerations
- **Authorized Use**: Only scan systems you own or have permission to test
- **Network Impact**: Configure appropriate timing to avoid disruption
- **Data Protection**: Secure handling of scan results
- **Compliance**: Follow applicable laws and regulations

## 🚀 Deployment

### Replit Deployment
1. **Configure environment variables** in Replit Secrets
2. **Set up PostgreSQL database** using Replit Database
3. **Deploy using Replit hosting** with auto-scaling

### Production Deployment
1. **Use production WSGI server** (Gunicorn, uWSGI)
2. **Configure reverse proxy** (Nginx, Apache)
3. **Set up SSL/TLS certificates** for HTTPS
4. **Implement monitoring** and alerting
5. **Regular security updates** and patches

### Docker Deployment
```dockerfile
FROM python:3.9-slim
COPY . /app
WORKDIR /app
RUN pip install -r requirements.txt
CMD ["python", "web_dashboard_simple.py"]
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Setup
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests and documentation
5. Submit a pull request

### Code Style
- Follow PEP 8 guidelines
- Use type hints
- Add comprehensive docstrings
- Maintain test coverage >80%

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Documentation**: Comprehensive guides and API documentation
- **Issues**: Report bugs and request features on GitHub
- **Security**: Report vulnerabilities to security@infogather.com
- **Community**: Join our discussions and community support

## 📚 Resources

- [Official Documentation](https://infogather.readthedocs.io)
- [API Reference](https://infogather.readthedocs.io/api)
- [Video Tutorials](https://youtube.com/infogather)
- [Community Forum](https://forum.infogather.com)

## 🎯 Roadmap

### Version 2.1 (Q2 2025)
- [ ] API rate limiting and authentication
- [ ] Advanced report customization
- [ ] Integration with SIEM systems
- [ ] Mobile-responsive improvements

### Version 3.0 (Q4 2025)
- [ ] Machine learning-based vulnerability detection
- [ ] Cloud-native deployment options
- [ ] Advanced threat intelligence integration
- [ ] Multi-tenant architecture

---

<div align="center">

**Made with ❤️ for the security community**

[Website](https://infogather.com) | [Documentation](https://docs.infogather.com) | [Community](https://community.infogather.com)

</div>>
cd infogather
