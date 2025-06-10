#!/usr/bin/env python3
"""
Input validation utilities for InfoGather
Enhanced security validation functions
"""

import re
import ipaddress
import socket
from urllib.parse import urlparse
from typing import Union, List

def validate_target(target):
    """
    Validate target input (IP address, hostname, or CIDR)

    Args:
        target (str): Target to validate

    Returns:
        bool: True if valid, False otherwise
    """
    if not target or not isinstance(target, str):
        return False

    target = target.strip()

    # Check length
    if len(target) > 255:
        return False

    # Check for malicious patterns
    malicious_patterns = [
        r'[;&|`$(){}[\]<>]',  # Shell metacharacters
        r'\.\./',              # Directory traversal
        r'javascript:',        # JavaScript injection
        r'data:',             # Data URIs
        r'file:',             # File URIs
    ]

    for pattern in malicious_patterns:
        if re.search(pattern, target, re.IGNORECASE):
            return False

    try:
        # Check if it's a valid IP address
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass

    try:
        # Check if it's a valid CIDR range
        ipaddress.ip_network(target, strict=False)
        return True
    except ValueError:
        pass

    # Check if it's a valid hostname/domain
    if validate_hostname(target):
        return True

    return False

def validate_hostname(hostname):
    """
    Validate hostname according to RFC standards

    Args:
        hostname (str): Hostname to validate

    Returns:
        bool: True if valid, False otherwise
    """
    if not hostname or len(hostname) > 253:
        return False

    # Remove trailing dot if present
    if hostname.endswith('.'):
        hostname = hostname[:-1]

    # Check each label
    labels = hostname.split('.')
    if not labels:
        return False

    for label in labels:
        if not label or len(label) > 63:
            return False

        # Label must start and end with alphanumeric
        if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$', label):
            return False

    # At least one dot for domain names (unless it's localhost)
    if len(labels) == 1 and hostname.lower() != 'localhost':
        return False

    return True

def validate_ports(ports):
    """
    Validate port specification

    Args:
        ports (str): Port specification (e.g., '80', '1-1000', '80,443,8080')

    Returns:
        bool: True if valid, False otherwise
    """
    if not ports or not isinstance(ports, str):
        return False

    ports = ports.strip()

    # Check for malicious patterns
    if re.search(r'[;&|`$(){}[\]<>]', ports):
        return False

    try:
        # Single port
        if ports.isdigit():
            port = int(ports)
            return 1 <= port <= 65535

        # Port range
        if '-' in ports and ports.count('-') == 1:
            start, end = ports.split('-')
            start_port = int(start.strip())
            end_port = int(end.strip())

            if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535):
                return False

            if start_port > end_port:
                return False

            # Prevent excessive ranges
            if end_port - start_port > 10000:
                return False

            return True

        # Comma-separated ports
        if ',' in ports:
            port_list = ports.split(',')
            if len(port_list) > 100:  # Limit number of ports
                return False

            for port in port_list:
                port = port.strip()
                if not port.isdigit():
                    return False

                port_num = int(port)
                if not (1 <= port_num <= 65535):
                    return False

            return True

    except (ValueError, AttributeError):
        return False

    return False

def validate_scan_modules(modules):
    """
    Validate scan module selection

    Args:
        modules (list): List of module names

    Returns:
        bool: True if valid, False otherwise
    """
    if not modules or not isinstance(modules, list):
        return False

    valid_modules = {
        'network_scan',
        'dns_enum', 
        'whois',
        'ssl_analysis',
        'vuln_scan',
        'social_intel',
        'advanced_dns',
        'cloud_assets'
    }

    # Check each module
    for module in modules:
        if not isinstance(module, str) or module not in valid_modules:
            return False

    # Limit number of modules
    if len(modules) > len(valid_modules):
        return False

    return True

def sanitize_filename(filename):
    """
    Sanitize filename for safe file operations

    Args:
        filename (str): Filename to sanitize

    Returns:
        str: Sanitized filename
    """
    if not filename:
        return 'unnamed'

    # Remove path separators and dangerous characters
    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
    filename = re.sub(r'\.\.', '_', filename)

    # Limit length
    if len(filename) > 100:
        filename = filename[:100]

    # Ensure it doesn't start with dot or dash
    filename = re.sub(r'^[.-]', '_', filename)

    return filename or 'unnamed'

def validate_json_input(data, max_size=1024*1024):
    """
    Validate JSON input for size and structure

    Args:
        data: JSON data to validate
        max_size (int): Maximum size in bytes

    Returns:
        bool: True if valid, False otherwise
    """
    try:
        import json
        json_str = json.dumps(data)

        # Check size
        if len(json_str.encode('utf-8')) > max_size:
            return False

        # Check depth (prevent deeply nested objects)
        def check_depth(obj, current_depth=0, max_depth=10):
            if current_depth > max_depth:
                return False

            if isinstance(obj, dict):
                return all(check_depth(v, current_depth + 1, max_depth) for v in obj.values())
            elif isinstance(obj, list):
                return all(check_depth(item, current_depth + 1, max_depth) for item in obj)

            return True

        return check_depth(data)

    except:
        return False

def validate_url(url: str) -> bool:
    """
    Validate URL format
    
    Args:
        url (str): URL to validate
        
    Returns:
        bool: True if URL is valid, False otherwise
    """
    if not url or not isinstance(url, str):
        return False
    
    try:
        result = urlparse(url.strip())
        # Check if scheme and netloc are present
        return all([result.scheme, result.netloc])
    except Exception:
        return False

def validate_email(email: str) -> bool:
    """
    Validate email address format
    
    Args:
        email (str): Email address to validate
        
    Returns:
        bool: True if email is valid, False otherwise
    """
    if not email or not isinstance(email, str):
        return False
    
    # Basic email validation regex
    email_pattern = re.compile(
        r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    )
    
    return bool(email_pattern.match(email.strip()))

def validate_domain(domain: str) -> bool:
    """
    Validate domain name format
    
    Args:
        domain (str): Domain name to validate
        
    Returns:
        bool: True if domain is valid, False otherwise
    """
    if not domain or not isinstance(domain, str):
        return False
    
    domain = domain.strip().lower()
    
    # Remove protocol if present
    if domain.startswith(('http://', 'https://')):
        domain = urlparse(domain).netloc
    
    return validate_hostname(domain)

def validate_file_path(file_path: str, allowed_extensions: list[str] = None) -> bool:
    """
    Validate file path and extension
    
    Args:
        file_path (str): File path to validate
        allowed_extensions (List[str]): List of allowed file extensions
        
    Returns:
        bool: True if file path is valid, False otherwise
    """
    if not file_path or not isinstance(file_path, str):
        return False
    
    file_path = file_path.strip()
    
    # Check for empty path
    if not file_path:
        return False
    
    # Check for directory traversal attempts
    if '..' in file_path or file_path.startswith('/'):
        return False
    
    # Check file extension if restrictions are specified
    if allowed_extensions:
        file_extension = file_path.lower().split('.')[-1] if '.' in file_path else ''
        if file_extension not in [ext.lower().lstrip('.') for ext in allowed_extensions]:
            return False
    
    return True

def sanitize_input(input_string: str, max_length: int = 1000) -> str:
    """
    Sanitize input string to prevent injection attacks
    
    Args:
        input_string (str): Input string to sanitize
        max_length (int): Maximum allowed length
        
    Returns:
        str: Sanitized string
    """
    if not input_string or not isinstance(input_string, str):
        return ""
    
    # Truncate to maximum length
    sanitized = input_string[:max_length]
    
    # Remove or escape potentially dangerous characters
    # Remove null bytes
    sanitized = sanitized.replace('\x00', '')
    
    # Remove control characters except for common whitespace
    sanitized = re.sub(r'[\x01-\x08\x0B\x0C\x0E-\x1F\x7F]', '', sanitized)
    
    # Strip leading/trailing whitespace
    sanitized = sanitized.strip()
    
    return sanitized

def validate_timing_template(timing: str) -> bool:
    """
    Validate nmap timing template
    
    Args:
        timing (str): Timing template to validate (T1-T5)
        
    Returns:
        bool: True if valid timing template, False otherwise
    """
    if not timing or not isinstance(timing, str):
        return False
    
    valid_templates = ['T1', 'T2', 'T3', 'T4', 'T5']
    return timing.upper() in valid_templates

def validate_scan_type(scan_type: str) -> bool:
    """
    Validate nmap scan type
    
    Args:
        scan_type (str): Scan type to validate
        
    Returns:
        bool: True if valid scan type, False otherwise
    """
    if not scan_type or not isinstance(scan_type, str):
        return False
    
    valid_scan_types = [
        'sS',  # TCP SYN scan
        'sT',  # TCP connect scan
        'sU',  # UDP scan
        'sN',  # TCP NULL scan
        'sF',  # TCP FIN scan
        'sX',  # TCP Xmas scan
        'sA',  # TCP ACK scan
        'sW',  # TCP Window scan
        'sM',  # TCP Maimon scan
        'sV',  # Version detection
        'sC',  # Script scan
        'O',   # OS detection
        'A',   # Aggressive scan
        'Pn',  # No ping
        'n',   # No DNS resolution
        'v',   # Verbose
        'vv',  # Very verbose
        'd',   # Debug
        'dd'   # Very debug
    ]
    
    return scan_type in valid_scan_types

def validate_output_format(output_format: str) -> bool:
    """
    Validate output format specification
    
    Args:
        output_format (str): Output format to validate
        
    Returns:
        bool: True if valid output format, False otherwise
    """
    if not output_format or not isinstance(output_format, str):
        return False
    
    valid_formats = ['text', 'json', 'html', 'xml', 'csv']
    return output_format.lower() in valid_formats

def validate_thread_count(thread_count: Union[str, int]) -> bool:
    """
    Validate thread count for parallel operations
    
    Args:
        thread_count (Union[str, int]): Thread count to validate
        
    Returns:
        bool: True if valid thread count, False otherwise
    """
    try:
        if isinstance(thread_count, str):
            thread_count = int(thread_count)
        
        # Check if it's a positive integer within reasonable bounds
        return isinstance(thread_count, int) and 1 <= thread_count <= 1000
    except (ValueError, TypeError):
        return False

def validate_timeout(timeout: Union[str, int, float]) -> bool:
    """
    Validate timeout value
    
    Args:
        timeout (Union[str, int, float]): Timeout value to validate
        
    Returns:
        bool: True if valid timeout, False otherwise
    """
    try:
        if isinstance(timeout, str):
            timeout = float(timeout)
        
        # Check if it's a positive number within reasonable bounds
        return isinstance(timeout, (int, float)) and 0.1 <= timeout <= 3600
    except (ValueError, TypeError):
        return False

def validate_cidr_size(cidr: str, max_hosts: int = 1024) -> bool:
    """
    Validate CIDR notation and check if network size is within limits
    
    Args:
        cidr (str): CIDR notation to validate
        max_hosts (int): Maximum number of hosts allowed
        
    Returns:
        bool: True if valid and within size limits, False otherwise
    """
    if not validate_target(cidr):
        return False
    
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return network.num_addresses <= max_hosts
    except Exception:
        return False

def is_safe_path(path: str, base_path: str = ".") -> bool:
    """
    Check if file path is safe (no directory traversal)
    
    Args:
        path (str): File path to check
        base_path (str): Base directory path
        
    Returns:
        bool: True if path is safe, False otherwise
    """
    try:
        import os.path
        
        # Resolve the path
        resolved_path = os.path.abspath(os.path.join(base_path, path))
        resolved_base = os.path.abspath(base_path)
        
        # Check if resolved path is within base directory
        return resolved_path.startswith(resolved_base)
    except Exception:
        return False

def validate_regex_pattern(pattern: str) -> bool:
    """
    Validate regular expression pattern
    
    Args:
        pattern (str): Regex pattern to validate
        
    Returns:
        bool: True if valid regex pattern, False otherwise
    """
    if not pattern or not isinstance(pattern, str):
        return False
    
    try:
        re.compile(pattern)
        return True
    except re.error:
        return False

def check_input_length(input_string: str, min_length: int = 0, max_length: int = 1000) -> bool:
    """
    Check if input string length is within specified bounds
    
    Args:
        input_string (str): Input string to check
        min_length (int): Minimum allowed length
        max_length (int): Maximum allowed length
        
    Returns:
        bool: True if length is within bounds, False otherwise
    """
    if not isinstance(input_string, str):
        return False
    
    return min_length <= len(input_string) <= max_length

def validate_wordlist_file(file_path: str) -> bool:
    """
    Validate wordlist file path and check if file exists and is readable
    
    Args:
        file_path (str): Path to wordlist file
        
    Returns:
        bool: True if file is valid and readable, False otherwise
    """
    import os
    
    if not file_path or not isinstance(file_path, str):
        return False
    
    # Check if path is safe
    if not is_safe_path(file_path):
        return False
    
    # Check if file exists and is readable
    try:
        return os.path.isfile(file_path) and os.access(file_path, os.R_OK)
    except Exception:
        return False

def sanitize_command_args(args: List[str]) -> List[str]:
    """
    Sanitize command line arguments to prevent injection
    
    Args:
        args (List[str]): List of command arguments
        
    Returns:
        List[str]: Sanitized arguments
    """
    if not args or not isinstance(args, list):
        return []
    
    sanitized_args = []
    
    for arg in args:
        if not isinstance(arg, str):
            continue
        
        # Remove dangerous characters and sequences
        sanitized_arg = arg.replace(';', '').replace('|', '').replace('&', '')
        sanitized_arg = sanitized_arg.replace('$(', '').replace('`', '')
        sanitized_arg = sanitized_arg.replace('\n', '').replace('\r', '')
        
        # Only keep if not empty after sanitization
        if sanitized_arg.strip():
            sanitized_args.append(sanitized_arg.strip())
    
    return sanitized_args