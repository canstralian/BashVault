"""
Network Utilities Module
Contains functions for network operations, IP handling, and CIDR expansion
"""

import socket
import ipaddress
import re
from typing import List, Union, Optional

def expand_cidr_range(cidr: str) -> List[str]:
    """
    Expand CIDR notation to list of IP addresses
    
    Args:
        cidr (str): CIDR notation (e.g., '192.168.1.0/24')
        
    Returns:
        List[str]: List of IP addresses in the range
        
    Raises:
        ValueError: If CIDR notation is invalid
    """
    try:
        # Parse the CIDR notation
        network = ipaddress.ip_network(cidr, strict=False)
        
        # For large networks, limit the number of IPs to prevent memory issues
        max_hosts = 1024  # Limit to 1024 hosts for safety
        
        if network.num_addresses > max_hosts:
            raise ValueError(f"Network too large ({network.num_addresses} hosts). "
                           f"Maximum allowed: {max_hosts}")
        
        # Convert network hosts to string list
        ip_list = [str(ip) for ip in network.hosts()]
        
        # For /31 and /32 networks, include network and broadcast addresses
        if network.prefixlen >= 31:
            ip_list = [str(network.network_address)]
            if network.prefixlen == 31:
                ip_list.append(str(network.broadcast_address))
        
        return ip_list
        
    except ipaddress.AddressValueError as e:
        raise ValueError(f"Invalid CIDR notation: {cidr}") from e
    except Exception as e:
        raise ValueError(f"Error expanding CIDR range: {str(e)}") from e

def is_valid_ip(ip_address: str) -> bool:
    """
    Check if string is a valid IP address (IPv4 or IPv6)
    
    Args:
        ip_address (str): IP address to validate
        
    Returns:
        bool: True if valid IP address, False otherwise
    """
    try:
        ipaddress.ip_address(ip_address)
        return True
    except ipaddress.AddressValueError:
        return False

def is_valid_ipv4(ip_address: str) -> bool:
    """
    Check if string is a valid IPv4 address
    
    Args:
        ip_address (str): IP address to validate
        
    Returns:
        bool: True if valid IPv4 address, False otherwise
    """
    try:
        ipaddress.IPv4Address(ip_address)
        return True
    except ipaddress.AddressValueError:
        return False

def is_valid_ipv6(ip_address: str) -> bool:
    """
    Check if string is a valid IPv6 address
    
    Args:
        ip_address (str): IP address to validate
        
    Returns:
        bool: True if valid IPv6 address, False otherwise
    """
    try:
        ipaddress.IPv6Address(ip_address)
        return True
    except ipaddress.AddressValueError:
        return False

def is_valid_cidr(cidr: str) -> bool:
    """
    Check if string is valid CIDR notation
    
    Args:
        cidr (str): CIDR notation to validate
        
    Returns:
        bool: True if valid CIDR notation, False otherwise
    """
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ipaddress.AddressValueError:
        return False

def is_valid_hostname(hostname: str) -> bool:
    """
    Check if string is a valid hostname/domain name
    
    Args:
        hostname (str): Hostname to validate
        
    Returns:
        bool: True if valid hostname, False otherwise
    """
    if not hostname or len(hostname) > 253:
        return False
    
    # Remove trailing dot if present
    if hostname.endswith('.'):
        hostname = hostname[:-1]
    
    # Check each label in the hostname
    labels = hostname.split('.')
    
    # Hostname must have at least one label
    if not labels:
        return False
    
    # Validate each label
    label_pattern = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$')
    
    for label in labels:
        if not label or len(label) > 63:
            return False
        if not label_pattern.match(label):
            return False
    
    return True

def get_ip_from_hostname(hostname: str, timeout: int = 5) -> Optional[str]:
    """
    Resolve hostname to IP address
    
    Args:
        hostname (str): Hostname to resolve
        timeout (int): DNS resolution timeout in seconds
        
    Returns:
        Optional[str]: IP address if resolution successful, None otherwise
    """
    try:
        # Set socket timeout for DNS resolution
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)
        
        try:
            ip_address = socket.gethostbyname(hostname)
            return ip_address
        finally:
            # Restore original timeout
            socket.setdefaulttimeout(old_timeout)
            
    except socket.gaierror:
        # DNS resolution failed
        return None
    except Exception:
        # Other errors
        return None

def get_hostname_from_ip(ip_address: str, timeout: int = 5) -> Optional[str]:
    """
    Perform reverse DNS lookup for IP address
    
    Args:
        ip_address (str): IP address to lookup
        timeout (int): DNS resolution timeout in seconds
        
    Returns:
        Optional[str]: Hostname if resolution successful, None otherwise
    """
    try:
        # Validate IP address first
        if not is_valid_ip(ip_address):
            return None
        
        # Set socket timeout for DNS resolution
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)
        
        try:
            hostname = socket.gethostbyaddr(ip_address)[0]
            return hostname
        finally:
            # Restore original timeout
            socket.setdefaulttimeout(old_timeout)
            
    except socket.herror:
        # Reverse DNS lookup failed
        return None
    except Exception:
        # Other errors
        return None

def is_private_ip(ip_address: str) -> bool:
    """
    Check if IP address is in private range (RFC 1918)
    
    Args:
        ip_address (str): IP address to check
        
    Returns:
        bool: True if IP is private, False otherwise
    """
    try:
        ip = ipaddress.ip_address(ip_address)
        return ip.is_private
    except ipaddress.AddressValueError:
        return False

def is_loopback_ip(ip_address: str) -> bool:
    """
    Check if IP address is loopback address
    
    Args:
        ip_address (str): IP address to check
        
    Returns:
        bool: True if IP is loopback, False otherwise
    """
    try:
        ip = ipaddress.ip_address(ip_address)
        return ip.is_loopback
    except ipaddress.AddressValueError:
        return False

def is_multicast_ip(ip_address: str) -> bool:
    """
    Check if IP address is multicast address
    
    Args:
        ip_address (str): IP address to check
        
    Returns:
        bool: True if IP is multicast, False otherwise
    """
    try:
        ip = ipaddress.ip_address(ip_address)
        return ip.is_multicast
    except ipaddress.AddressValueError:
        return False

def get_network_info(ip_address: str, netmask: str = None) -> dict:
    """
    Get network information for IP address
    
    Args:
        ip_address (str): IP address
        netmask (str): Network mask (optional)
        
    Returns:
        dict: Network information
    """
    info = {
        'ip_address': ip_address,
        'is_valid': False,
        'version': None,
        'is_private': False,
        'is_loopback': False,
        'is_multicast': False,
        'network': None,
        'broadcast': None
    }
    
    try:
        ip = ipaddress.ip_address(ip_address)
        info['is_valid'] = True
        info['version'] = ip.version
        info['is_private'] = ip.is_private
        info['is_loopback'] = ip.is_loopback
        info['is_multicast'] = ip.is_multicast
        
        # If netmask provided, calculate network info
        if netmask:
            if '/' in netmask:
                # CIDR notation
                network = ipaddress.ip_network(f"{ip_address}/{netmask.split('/')[1]}", strict=False)
            else:
                # Netmask notation
                network = ipaddress.ip_network(f"{ip_address}/{netmask}", strict=False)
            
            info['network'] = str(network.network_address)
            info['broadcast'] = str(network.broadcast_address)
            info['netmask'] = str(network.netmask)
            info['prefix_length'] = network.prefixlen
            info['num_addresses'] = network.num_addresses
            
    except Exception as e:
        info['error'] = str(e)
    
    return info

def port_range_to_list(port_range: str) -> List[int]:
    """
    Convert port range string to list of port numbers
    
    Args:
        port_range (str): Port range (e.g., "1-1000", "80,443,8080", "22")
        
    Returns:
        List[int]: List of port numbers
        
    Raises:
        ValueError: If port range is invalid
    """
    ports = []
    
    try:
        # Handle comma-separated ports
        if ',' in port_range:
            port_parts = port_range.split(',')
            for part in port_parts:
                part = part.strip()
                if '-' in part:
                    # Handle range within comma-separated list
                    start, end = map(int, part.split('-', 1))
                    if start > end or start < 1 or end > 65535:
                        raise ValueError(f"Invalid port range: {part}")
                    ports.extend(range(start, end + 1))
                else:
                    # Single port
                    port = int(part)
                    if port < 1 or port > 65535:
                        raise ValueError(f"Invalid port number: {port}")
                    ports.append(port)
        
        # Handle range
        elif '-' in port_range:
            start, end = map(int, port_range.split('-', 1))
            if start > end or start < 1 or end > 65535:
                raise ValueError(f"Invalid port range: {port_range}")
            ports = list(range(start, end + 1))
        
        # Single port
        else:
            port = int(port_range)
            if port < 1 or port > 65535:
                raise ValueError(f"Invalid port number: {port}")
            ports = [port]
        
        # Remove duplicates and sort
        ports = sorted(list(set(ports)))
        
        # Limit number of ports for performance
        max_ports = 10000
        if len(ports) > max_ports:
            raise ValueError(f"Too many ports specified ({len(ports)}). Maximum: {max_ports}")
        
        return ports
        
    except ValueError:
        raise
    except Exception as e:
        raise ValueError(f"Error parsing port range: {str(e)}") from e

def is_port_in_range(port: int, port_range: str) -> bool:
    """
    Check if port is within specified range
    
    Args:
        port (int): Port number to check
        port_range (str): Port range specification
        
    Returns:
        bool: True if port is in range, False otherwise
    """
    try:
        ports = port_range_to_list(port_range)
        return port in ports
    except ValueError:
        return False

def get_common_ports() -> dict:
    """
    Get dictionary of common ports and their services
    
    Returns:
        dict: Dictionary mapping port numbers to service names
    """
    return {
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        143: 'IMAP',
        443: 'HTTPS',
        993: 'IMAPS',
        995: 'POP3S',
        465: 'SMTPS',
        587: 'SMTP Submission',
        3389: 'RDP',
        5432: 'PostgreSQL',
        3306: 'MySQL',
        1433: 'MSSQL',
        6379: 'Redis',
        27017: 'MongoDB',
        5984: 'CouchDB',
        9200: 'Elasticsearch',
        8080: 'HTTP Alternate',
        8443: 'HTTPS Alternate',
        8000: 'HTTP Development',
        3000: 'Node.js Development'
    }

def calculate_subnet_info(cidr: str) -> dict:
    """
    Calculate detailed subnet information from CIDR notation
    
    Args:
        cidr (str): CIDR notation (e.g., '192.168.1.0/24')
        
    Returns:
        dict: Detailed subnet information
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        
        info = {
            'network_address': str(network.network_address),
            'broadcast_address': str(network.broadcast_address),
            'netmask': str(network.netmask),
            'wildcard_mask': str(network.hostmask),
            'prefix_length': network.prefixlen,
            'num_addresses': network.num_addresses,
            'num_hosts': network.num_addresses - 2 if network.num_addresses > 2 else network.num_addresses,
            'first_host': str(list(network.hosts())[0]) if list(network.hosts()) else str(network.network_address),
            'last_host': str(list(network.hosts())[-1]) if list(network.hosts()) else str(network.network_address),
            'is_private': network.is_private,
            'version': network.version
        }
        
        return info
        
    except Exception as e:
        return {'error': f"Error calculating subnet info: {str(e)}"}
