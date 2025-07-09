# InfoGather - Penetration Testing Tool

## Overview

InfoGather is a comprehensive Python-based penetration testing and information gathering tool designed for authorized security assessments. The project includes both a command-line interface and a modern web dashboard for conducting network reconnaissance, vulnerability scanning, and generating detailed security reports.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Frontend Architecture
- **Web Dashboard**: Flask-based web application with responsive Bootstrap 5 UI
- **Templates**: Jinja2 templating engine for dynamic content rendering
- **Client-Side**: JavaScript with real-time updates and interactive scanning interface
- **Styling**: Modern CSS with custom dashboard theme and mobile-responsive design

### Backend Architecture
- **Core Framework**: Flask web application with session management
- **Database Options**: 
  - Primary: PostgreSQL with SQLAlchemy ORM (models.py)
  - Fallback: SQLite for development/testing
- **Authentication**: Username/password with secure session management
- **Modular Design**: Separate modules for different scanning capabilities

### Key Components

#### Scanning Modules
- **Network Scanner**: Host discovery and port scanning using nmap
- **DNS Enumerator**: Subdomain discovery and DNS record analysis
- **SSL Analyzer**: Certificate validation and TLS configuration assessment
- **Vulnerability Scanner**: Basic security vulnerability detection
- **Advanced DNS**: DNS over HTTPS bypass and certificate transparency mining
- **Social Engineer**: Employee enumeration and email pattern discovery
- **Cloud Discovery**: AWS S3, Azure blob, and Google Cloud storage enumeration
- **Threat Monitor**: Real-time threat intelligence and monitoring

#### Core Utilities
- **Network Utils**: CIDR expansion, IP validation, hostname resolution
- **Validation**: Input sanitization and security validation
- **Report Generator**: Multi-format reporting (text, JSON, HTML)

#### Web Dashboard Features
- **Real-time Scanning**: Asynchronous scan execution with progress tracking
- **Scan History**: Persistent scan result storage and retrieval
- **User Management**: Multi-user support with authentication
- **Threat Monitoring**: Asset monitoring and vulnerability tracking

## Data Flow

### Scan Execution Flow
1. User configures scan parameters through web interface
2. Scan request validated and queued with unique ID
3. Selected modules execute in parallel with progress updates
4. Results stored in database with structured format
5. Real-time updates sent to frontend via polling
6. Final report generated in multiple formats

### Database Schema
- **Users**: User authentication and profile management
- **Scans**: Scan configuration and execution metadata
- **ScanResults**: Detailed scan findings and data
- **Findings**: Vulnerability and security issues
- **AuditLog**: Security audit trail

## External Dependencies

### Python Libraries
- **nmap**: Network scanning capabilities
- **requests**: HTTP operations and API calls
- **dnspython**: DNS operations and queries
- **python-whois**: Domain information gathering
- **cryptography**: SSL/TLS certificate analysis
- **flask**: Web framework
- **flask-sqlalchemy**: Database ORM
- **psycopg2**: PostgreSQL database adapter
- **jinja2**: Template engine

### System Requirements
- **nmap binary**: Required for network scanning
- **PostgreSQL**: Primary database (with SQLite fallback)
- **Python 3.7+**: Runtime environment

### Security Considerations
- **Input Validation**: Comprehensive validation against injection attacks
- **Session Security**: Secure session management with proper secret keys
- **Database Security**: Connection pooling and prepared statements
- **Thread Safety**: Proper synchronization for concurrent operations

## Deployment Strategy

### Development Environment
- **Replit Integration**: Configured for Replit deployment
- **Environment Variables**: Database URL and secret keys via environment
- **Auto-Migration**: Database schema creation on startup

### Production Considerations
- **PostgreSQL**: Scalable database with connection pooling
- **Security**: Hardened authentication and input validation
- **Performance**: Multi-threaded scanning with resource limits
- **Monitoring**: Comprehensive audit logging and error tracking

### Configuration
- **Database**: Auto-configuration via DATABASE_URL environment variable
- **Security**: Secure secret key generation and password hashing
- **Scaling**: Thread-safe operations with proper resource management

## Security Features

### Authentication & Authorization
- **User Management**: Secure user registration and login
- **Session Management**: Persistent sessions with secure cookies
- **Role-Based Access**: User role support for multi-tenant usage

### Security Hardening
- **Input Validation**: Protection against injection attacks
- **Resource Limits**: Scan timeout and resource consumption limits
- **Audit Logging**: Comprehensive security event logging
- **Error Handling**: Graceful error handling without information disclosure

### Compliance
- **Ethical Use**: Built-in disclaimers and ethical use warnings
- **Authorized Testing**: Emphasis on authorized security testing only
- **Documentation**: Clear usage guidelines and legal considerations

## Recent Changes (v2.0.0 - Production Ready)

### Added Production-Ready Features (July 2025)
- **CI/CD Pipeline**: GitHub Actions with automated testing, security scanning, and deployment
- **Comprehensive Testing**: Unit tests, integration tests, and security tests with >80% coverage
- **Health Monitoring**: Health check, readiness, and liveness endpoints for monitoring
- **Security Hardening**: Input validation, rate limiting, and security scanning
- **Documentation**: Complete README, contributing guidelines, and changelog
- **Docker Support**: Production-ready Docker containers with PostgreSQL and Redis
- **Type Safety**: Full type hints and PEP 8 compliance
- **Structured Logging**: Comprehensive logging and monitoring capabilities

### Code Quality Improvements
- **Black Code Formatting**: Consistent code style across the project
- **MyPy Type Checking**: Static type checking for better code quality
- **Flake8 Linting**: Code quality enforcement and style checking
- **Bandit Security Scanning**: Automated security vulnerability detection
- **Safety Dependency Checking**: Regular dependency vulnerability scanning

### Enhanced Architecture
- **Modular Design**: Improved separation of concerns and modularity
- **Error Handling**: Comprehensive error handling and graceful degradation
- **Configuration Management**: Environment-based configuration with .env support
- **Production Deployment**: Replit-optimized deployment with auto-scaling
- **Database Migrations**: Proper database schema management

### Security Enhancements
- **Authentication**: Secure user authentication with session management
- **Authorization**: Role-based access control and user permissions
- **Input Validation**: Comprehensive input sanitization and validation
- **Rate Limiting**: DDoS protection and abuse prevention
- **Audit Logging**: Complete audit trail for security events

### Performance Optimizations
- **Parallel Processing**: Multi-threaded scanning with improved performance
- **Memory Management**: Automated cleanup and resource management
- **Connection Pooling**: Efficient database connection management
- **Caching**: Result caching for improved response times

### Deployment Configuration
- **Environment Variables**: Complete environment variable management
- **Health Checks**: Monitoring endpoints for production deployment
- **Docker Containers**: Production-ready containerization
- **Nginx Configuration**: Reverse proxy with security headers and rate limiting
- **SSL/TLS Support**: HTTPS configuration for secure communications

### Version Control and Governance
- **Git Configuration**: Proper .gitignore and version control setup
- **Semantic Versioning**: SemVer compliance with proper changelog
- **MIT License**: Open source license with proper attribution
- **Contributing Guidelines**: Clear guidelines for contributors
- **Code of Conduct**: Professional development environment standards