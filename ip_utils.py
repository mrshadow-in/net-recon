"""
IP Utilities Module for ROCON Tools
Provides functionality for IP address validation, parsing, and range generation.
"""
import ipaddress
from typing import List, Tuple, Union


def validate_ip(ip: str) -> bool:
    """
    Validate if a string is a valid IPv4 address.
    
    Args:
        ip: String representation of an IP address
        
    Returns:
        bool: True if valid IPv4 address, False otherwise
    """
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ValueError:
        return False


def validate_subnet(subnet: str) -> bool:
    """
    Validate if a string is a valid IPv4 subnet in CIDR notation.
    
    Args:
        subnet: String representation of a subnet (e.g., "192.168.1.0/24")
        
    Returns:
        bool: True if valid IPv4 subnet, False otherwise
    """
    # Check if the subnet string contains a '/' character (CIDR notation)
    if '/' not in subnet:
        return False
    
    try:
        ipaddress.IPv4Network(subnet, strict=False)
        return True
    except (ValueError, ipaddress.AddressValueError, ipaddress.NetmaskValueError):
        return False


def get_ip_range(start_ip: str, end_ip: str) -> List[str]:
    """
    Generate a list of IP addresses from start_ip to end_ip (inclusive).
    
    Args:
        start_ip: Starting IP address
        end_ip: Ending IP address
        
    Returns:
        List[str]: List of IP addresses in the range
        
    Raises:
        ValueError: If start_ip or end_ip is invalid or if start_ip > end_ip
    """
    if not validate_ip(start_ip) or not validate_ip(end_ip):
        raise ValueError("Invalid IP address provided")
    
    start = int(ipaddress.IPv4Address(start_ip))
    end = int(ipaddress.IPv4Address(end_ip))
    
    if start > end:
        # Swap if start is greater than end
        start, end = end, start
    
    return [str(ipaddress.IPv4Address(ip)) for ip in range(start, end + 1)]


def get_ips_from_subnet(subnet: str) -> List[str]:
    """
    Generate a list of all usable IP addresses in the given subnet.
    
    Args:
        subnet: Subnet in CIDR notation (e.g., "192.168.1.0/24")
        
    Returns:
        List[str]: List of all usable IP addresses in the subnet
        
    Raises:
        ValueError: If subnet is invalid
    """
    if not validate_subnet(subnet):
        raise ValueError(f"Invalid subnet: {subnet}")
    
    network = ipaddress.IPv4Network(subnet, strict=False)
    # Skip network address and broadcast address for subnets larger than /31
    if network.prefixlen < 31:
        hosts = list(network.hosts())
    else:
        hosts = list(network)
    
    return [str(ip) for ip in hosts]


def parse_ip_input(start_ip: str = None, end_ip: str = None, subnet: str = None) -> List[str]:
    """
    Parse user input and return a list of IP addresses to scan.
    
    Args:
        start_ip: Starting IP address for range scan
        end_ip: Ending IP address for range scan
        subnet: Subnet in CIDR notation for subnet scan
        
    Returns:
        List[str]: List of IP addresses to scan
        
    Raises:
        ValueError: If inputs are invalid or insufficient
    """
    if subnet and validate_subnet(subnet):
        return get_ips_from_subnet(subnet)
    elif start_ip and end_ip and validate_ip(start_ip) and validate_ip(end_ip):
        return get_ip_range(start_ip, end_ip)
    else:
        raise ValueError("Invalid or insufficient IP input provided")