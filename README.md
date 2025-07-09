# InfoGather v1.0.0 🛡️

[![CI/CD Pipeline](https://github.com/username/infogather/actions/workflows/ci.yml/badge.svg)](https://github.com/username/infogather/actions/workflows/ci.yml)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=infogather&metric=security_rating)](https://sonarcloud.io/dashboard?id=infogather)
[![Coverage](https://codecov.io/gh/username/infogather/branch/main/graph/badge.svg)](https://codecov.io/gh/username/infogather)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

InfoGather is a comprehensive, production-ready penetration testing and information gathering tool designed for authorized security assessments. It combines powerful reconnaissance capabilities with a modern web interface for efficient security testing workflows.

## 🚀 Features

### Core Capabilities
- **Network Scanning** - Port discovery and service enumeration
- **DNS Enumeration** - Subdomain discovery and DNS intelligence
- **SSL/TLS Analysis** - Certificate validation and security assessment
- **Vulnerability Scanning** - Automated security vulnerability detection
- **Social Engineering Intelligence** - OSINT data gathering
- **Advanced DNS Analysis** - DNS tunneling and covert channel detection
- **Cloud Asset Discovery** - AWS, Azure, GCP resource enumeration

### Web Dashboard
- **Real-time Monitoring** - Live scan progress and threat monitoring
- **Historical Analysis** - Comprehensive scan history and trends
- **Export Capabilities** - JSON, HTML, and PDF report generation
- **User Management** - Multi-user support with authentication
- **RESTful API** - Programmatic access to all functionality

### Security Features
- **Authentication & Authorization** - Secure user management
- **Input Validation** - Comprehensive sanitization and validation
- **Rate Limiting** - DDoS protection and abuse prevention
- **Audit Logging** - Complete security event tracking
- **HTTPS Support** - SSL/TLS encryption for all communications

## 📋 Requirements

- Python 3.8+
- PostgreSQL 12+
- Modern web browser (Chrome, Firefox, Safari, Edge)
- Minimum 2GB RAM, 1GB storage

## 🛠️ Installation

### Quick Start (Replit)

[![Run on Replit](https://replit.com/badge/github/username/infogather)](https://replit.com/new/github/username/infogather)

1. Click the "Run on Replit" button above
2. Configure environment variables (see Configuration section)
3. Run the application using the provided workflow

### Manual Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/username/infogather.git
   cd infogather
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure environment**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

4. **Initialize database**
   ```bash
   python -c "from app import create_app; from web_dashboard_simple import init_database; init_database()"
   ```

5. **Run the application**
   ```bash
   python app.py
   ```

## ⚙️ Configuration

### Environment Variables

Copy `.env.example` to `.env` and configure:

```env
# Basic Configuration
FLASK_ENV=production
SECRET_KEY=your-secret-key-here
DATABASE_URL=postgresql://user:pass@localhost/infogather

# Admin Account
ADMIN_USERNAME=admin
ADMIN_PASSWORD=secure-password

# Security Settings
MAX_CONCURRENT_SCANS=5
SCAN_TIMEOUT=3600
LOG_LEVEL=INFO
```

### Database Setup

For PostgreSQL:
```sql
CREATE DATABASE infogather;
CREATE USER infogather WITH PASSWORD 'secure_password';
GRANT ALL PRIVILEGES ON DATABASE infogather TO infogather;
```

## 🚀 Usage

### Web Interface

1. **Access the dashboard**: `http://your-domain:5000`
2. **Login** with admin credentials
3. **Configure scan** - Select target and modules
4. **Monitor progress** - Real-time scan updates
5. **Review results** - Comprehensive findings analysis
6. **Export reports** - Multiple format options

### Command Line Interface

```bash
# Basic scan
python pentester.py -t example.com --all-modules

# Advanced scan with custom options
python pentester.py -t 192.168.1.0/24 -p 1-1000 --timing T4 --threads 100

# Specific modules
python pentester.py -t example.com --network-scan --dns-enum --ssl-analysis
```

### API Usage

```python
import requests

# Start a scan
response = requests.post('https://your-domain/api/start_scan', 
                        json={
                            'target': 'example.com',
                            'modules': ['network_scan', 'dns_enum'],
                            'ports': '1-1000'
                        })

scan_id = response.json()['scan_id']

# Check status
status = requests.get(f'https://your-domain/api/scan_status/{scan_id}')

# Get results
results = requests.get(f'https://your-domain/api/scan_results/{scan_id}')
```

## 🔒 Security Considerations

### ⚠️ **Legal Disclaimer**
InfoGather is intended for **authorized security testing only**. Users must ensure they have explicit written permission before scanning any networks or systems they do not own. Unauthorized use may violate laws and regulations.

### Security Best Practices

1. **Use strong authentication** - Enable strong passwords and consider 2FA
2. **Restrict network access** - Use firewalls and VPN access
3. **Regular updates** - Keep dependencies and system updated
4. **Monitor logs** - Review audit logs regularly
5. **Backup data** - Implement regular backup procedures

### Security Features

- **Input sanitization** - Protection against injection attacks
- **Rate limiting** - Prevents abuse and DDoS attacks
- **Session management** - Secure session handling with timeouts
- **Audit logging** - Comprehensive security event tracking
- **HTTPS encryption** - All communications encrypted

## 🧪 Testing

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=. --cov-report=html

# Run specific test categories
pytest -m "not slow"  # Skip slow tests
pytest -m "security"  # Run security tests only
```

### Test Categories

- **Unit Tests** - Individual component testing
- **Integration Tests** - End-to-end functionality
- **Security Tests** - Vulnerability and penetration testing
- **Performance Tests** - Load and stress testing

## 📊 Monitoring

### Health Checks

- **Basic Health**: `/health` - Application status
- **Readiness**: `/health/ready` - Database connectivity
- **Liveness**: `/health/live` - Process status

### Metrics

- **Scan Statistics** - Success rates, performance metrics
- **User Activity** - Login attempts, scan frequency
- **System Resources** - CPU, memory, disk usage
- **Security Events** - Failed logins, blocked IPs

## 🔄 CI/CD Pipeline

### GitHub Actions

The project includes comprehensive CI/CD:

- **Code Quality** - Linting, formatting, type checking
- **Security Scanning** - Vulnerability detection, dependency audit
- **Testing** - Unit, integration, security tests
- **Deployment** - Automated Replit deployment
- **Monitoring** - Post-deployment health checks

### Deployment Process

1. **Development** - Feature branches with PR reviews
2. **Testing** - Automated test suite execution
3. **Security** - Vulnerability scanning and auditing
4. **Staging** - Deploy to staging environment
5. **Production** - Automated production deployment
6. **Monitoring** - Post-deployment verification

## 📚 API Documentation

### Authentication

All API endpoints require authentication via session cookies or API keys.

### Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/start_scan` | Start a new scan |
| GET | `/api/scan_status/{id}` | Get scan status |
| GET | `/api/scan_results/{id}` | Get scan results |
| GET | `/api/dashboard_stats` | Get dashboard statistics |
| DELETE | `/api/delete_scan/{id}` | Delete a scan |

### Request/Response Examples

See [API Documentation](docs/api.md) for detailed examples.

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

### Code Standards

- **Python**: PEP 8 compliance, type hints
- **JavaScript**: ES6+, consistent formatting
- **Testing**: >80% code coverage required
- **Security**: All changes security reviewed

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

### Documentation

- [Installation Guide](docs/installation.md)
- [Configuration Reference](docs/configuration.md)
- [API Documentation](docs/api.md)
- [Troubleshooting](docs/troubleshooting.md)

### Community

- [GitHub Issues](https://github.com/username/infogather/issues)
- [Security Reports](security@infogather.com)
- [Feature Requests](https://github.com/username/infogather/discussions)

## 🔄 Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history and updates.

## 🏆 Acknowledgments

- [OWASP](https://owasp.org/) for security best practices
- [Nmap](https://nmap.org/) for network scanning capabilities
- [DNSRecon](https://github.com/darkoperator/dnsrecon) for DNS enumeration
- Contributors and security researchers

---

**Remember**: Always ensure you have proper authorization before using InfoGather on any network or system. Use responsibly and ethically.