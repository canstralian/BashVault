"""
InfoGather Utilities Package
Contains utility functions for network operations, validation, and common tasks
"""

__version__ = "1.0.0"
__author__ = "InfoGather Team"

from .network_utils import expand_cidr_range, is_valid_ip, is_valid_cidr, get_ip_from_hostname
from .validation import validate_target, validate_ports, validate_url, sanitize_input

__all__ = [
    'expand_cidr_range',
    'is_valid_ip', 
    'is_valid_cidr',
    'get_ip_from_hostname',
    'validate_target',
    'validate_ports',
    'validate_url',
    'sanitize_input'
]
