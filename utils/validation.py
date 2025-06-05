"""
Validation Utilities Module
Contains functions for input validation and sanitization
"""

import re
import socket
import ipaddress
from urllib.parse import urlparse
from typing import Union, List, Optional
from .network_utils import is_valid_ip, is_valid_cidr, is_valid_hostname, port_range_to_list

def validate_target(target: str) -> bool:
    """
    Validate target specification (IP, hostname, or CIDR)
    
    Args:
        target (str): Target to validate
        
    Returns:
        bool: True if target is valid, False otherwise
    """
    if not target or not isinstance(target, str):
        return False
    
    target = target.strip()
    
    # Check if empty after stripping
    if not target:
        return False
    
    # Check for CIDR notation
    if '/' in target:
        return is_valid_cidr(target)
    
    # Check if it's an IP address
    if is_valid_ip(target):
        return True
    
    # Check if it's a valid hostname
    if is_valid_hostname(target):
        return True
    
    return False

def validate_ports(ports: str) -> bool:
    """
    Validate port specification
    
    Args:
        ports (str): Port specification to validate
        
    Returns:
        bool: True if ports specification is valid, False otherwise
    """
    if not ports or not isinstance(ports, str):
        return False
    
    try:
        # Use the port_range_to_list function to validate
        port_list = port_range_to_list(ports.strip())
        return len(port_list) > 0
    except ValueError:
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
    
    return is_valid_hostname(domain)

def validate_file_path(file_path: str, allowed_extensions: List[str] = None) -> bool:
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

def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename to be safe for file system
    
    Args:
        filename (str): Filename to sanitize
        
    Returns:
        str: Sanitized filename
    """
    if not filename or not isinstance(filename, str):
        return "untitled"
    
    # Remove or replace invalid filename characters
    invalid_chars = '<>:"/\\|?*'
    sanitized = filename
    
    for char in invalid_chars:
        sanitized = sanitized.replace(char, '_')
    
    # Remove control characters
    sanitized = re.sub(r'[\x00-\x1F\x7F]', '', sanitized)
    
    # Remove leading/trailing dots and spaces
    sanitized = sanitized.strip('. ')
    
    # Ensure filename is not empty
    if not sanitized:
        sanitized = "untitled"
    
    # Limit length
    max_length = 255
    if len(sanitized) > max_length:
        name, ext = sanitized.rsplit('.', 1) if '.' in sanitized else (sanitized, '')
        if ext:
            max_name_length = max_length - len(ext) - 1
            sanitized = f"{name[:max_name_length]}.{ext}"
        else:
            sanitized = sanitized[:max_length]
    
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
    if not is_valid_cidr(cidr):
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
