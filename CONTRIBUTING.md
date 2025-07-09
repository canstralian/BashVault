# Contributing to InfoGather

Thank you for your interest in contributing to InfoGather! This document provides guidelines for contributing to this penetration testing and security assessment tool.

## Code of Conduct

By participating in this project, you agree to maintain a respectful and professional environment. We are committed to providing a harassment-free experience for everyone.

## Security and Legal Considerations

⚠️ **IMPORTANT**: This tool is designed for authorized security testing only. All contributions must:

1. Include appropriate legal disclaimers
2. Emphasize authorized use only
3. Not facilitate illegal activities
4. Follow responsible disclosure practices

## How to Contribute

### Reporting Issues

1. Check if the issue already exists in the issue tracker
2. Use the appropriate issue template
3. Provide detailed reproduction steps
4. Include system information and error messages
5. For security vulnerabilities, follow our security policy

### Submitting Changes

1. **Fork the repository**
2. **Create a feature branch** (`git checkout -b feature/amazing-feature`)
3. **Make your changes** following our coding standards
4. **Add tests** for new functionality
5. **Run the test suite** (`pytest`)
6. **Run code quality checks** (`black`, `flake8`, `mypy`)
7. **Commit your changes** (`git commit -m 'Add amazing feature'`)
8. **Push to the branch** (`git push origin feature/amazing-feature`)
9. **Open a Pull Request**

### Development Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/your-username/infogather.git
   cd infogather
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up environment variables**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

4. **Initialize database**
   ```bash
   python -c "from web_dashboard_simple import init_database; init_database()"
   ```

5. **Run tests**
   ```bash
   pytest
   ```

## Coding Standards

### Python Style Guide

- Follow PEP 8 style guidelines
- Use type hints for all functions and methods
- Maximum line length: 88 characters (Black formatter)
- Use meaningful variable and function names

### Code Quality Tools

- **Black**: Code formatting
- **Flake8**: Linting
- **MyPy**: Type checking
- **Bandit**: Security scanning
- **Pytest**: Testing framework

### Running Quality Checks

```bash
# Format code
black .

# Check linting
flake8 .

# Type checking
mypy .

# Security scanning
bandit -r .

# Run tests with coverage
pytest --cov=. --cov-report=html
```

## Testing Guidelines

### Test Coverage

- Maintain >80% test coverage
- Write unit tests for all modules
- Include integration tests for web dashboard
- Test error handling and edge cases

### Test Structure

```python
import pytest
from unittest.mock import Mock, patch

class TestModuleName:
    def test_functionality(self):
        # Arrange
        # Act
        # Assert
        pass
```

## Documentation

### Code Documentation

- Use docstrings for all functions, classes, and modules
- Follow Google-style docstrings
- Include parameter types and return values
- Provide usage examples

### API Documentation

- Document all API endpoints
- Include request/response examples
- Specify authentication requirements
- Document error responses

## Security Guidelines

### Input Validation

- Validate all user inputs
- Sanitize data before database operations
- Use parameterized queries
- Implement rate limiting

### Authentication & Authorization

- Use secure session management
- Implement proper password hashing
- Add audit logging for security events
- Follow principle of least privilege

### Vulnerability Disclosure

If you discover a security vulnerability:

1. **Do not** open a public issue
2. Email security@infogather.com
3. Provide detailed reproduction steps
4. Allow reasonable time for response
5. Follow coordinated disclosure practices

## Module Development

### Creating New Modules

1. Create module in `modules/` directory
2. Follow the existing module structure
3. Implement proper error handling
4. Add comprehensive tests
5. Update documentation

### Module Template

```python
"""
Module Name - Description
"""

import logging
from typing import Dict, List, Optional

class ModuleName:
    def __init__(self, verbose: bool = False, timeout: int = 10):
        self.verbose = verbose
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)
    
    def analyze(self, target: str) -> Dict:
        """Main analysis method"""
        try:
            # Implementation
            return {}
        except Exception as e:
            self.logger.error(f"Analysis error: {e}")
            return {'error': str(e)}
```

## Release Process

### Versioning

- Use Semantic Versioning (SemVer)
- Update `CHANGELOG.md` with each release
- Tag releases with git tags

### Release Checklist

- [ ] All tests pass
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
- [ ] Version number bumped
- [ ] Security scan completed
- [ ] Performance tests pass

## Getting Help

- Check existing documentation
- Search closed issues
- Ask questions in discussions
- Contact maintainers

## Recognition

Contributors will be recognized in:
- README.md contributors section
- Release notes
- Project documentation

Thank you for contributing to InfoGather!