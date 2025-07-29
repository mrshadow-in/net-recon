"""
Output Formatter Module for ROCON Tools
Provides functionality for formatting and displaying scan results in a beautified manner.
"""
from typing import List, Dict, Any, Tuple
import json
from datetime import datetime
import os
import shutil


def format_ip_list(ip_list: List[str], status: str, colored: bool = True) -> str:
    """
    Format a list of IP addresses with their status.
    
    Args:
        ip_list: List of IP addresses
        status: Status of the IPs ('active' or 'inactive')
        colored: Whether to use ANSI color codes
        
    Returns:
        str: Formatted string representation of the IP list
    """
    if not ip_list:
        return f"No {status} IPs found."
    
    # ANSI color codes
    GREEN = '\033[92m' if colored else ''
    RED = '\033[91m' if colored else ''
    RESET = '\033[0m' if colored else ''
    
    color = GREEN if status == 'active' else RED
    
    header = f"{color}{status.upper()} IPs ({len(ip_list)}):{RESET}"
    formatted_ips = []
    
    # Format IPs in columns
    column_width = 20
    num_columns = 4
    
    for i in range(0, len(ip_list), num_columns):
        row_ips = ip_list[i:i+num_columns]
        row = "  ".join(f"{ip:<{column_width}}" for ip in row_ips)
        formatted_ips.append(row)
    
    return header + "\n" + "\n".join(formatted_ips)


def format_scan_results(active_ips: List[str], inactive_ips: List[str], scan_info: Dict[str, Any] = None) -> str:
    """
    Format the complete scan results for console display.
    
    Args:
        active_ips: List of active IP addresses
        inactive_ips: List of inactive IP addresses
        scan_info: Additional scan information
        
    Returns:
        str: Formatted string representation of the scan results
    """
    # Create a horizontal line for separation
    separator = "=" * 80
    
    # Format header with scan information
    header = ["ROCON IP SCANNER - SCAN RESULTS", separator]
    if scan_info:
        timestamp = scan_info.get('timestamp', datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        duration = scan_info.get('duration', 'N/A')
        scan_type = scan_info.get('scan_type', 'IP Scan')
        
        header.extend([
            f"Timestamp: {timestamp}",
            f"Duration: {duration:.2f} seconds" if isinstance(duration, (int, float)) else f"Duration: {duration}",
            f"Scan Type: {scan_type}",
            separator
        ])
    
    # Format active and inactive IP lists
    active_section = format_ip_list(active_ips, 'active')
    inactive_section = format_ip_list(inactive_ips, 'inactive')
    
    # Combine all sections
    sections = header + ["", active_section, "", inactive_section, "", separator]
    
    return "\n".join(sections)


def get_results_summary(active_ips: List[str], inactive_ips: List[str], scan_info: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Create a summary dictionary of the scan results.
    
    Args:
        active_ips: List of active IP addresses
        inactive_ips: List of inactive IP addresses
        scan_info: Additional scan information
        
    Returns:
        Dict[str, Any]: Summary of the scan results
    """
    total_ips = len(active_ips) + len(inactive_ips)
    active_percentage = (len(active_ips) / total_ips * 100) if total_ips > 0 else 0
    
    summary = {
        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'total_ips_scanned': total_ips,
        'active_ips': {
            'count': len(active_ips),
            'percentage': active_percentage,
            'ips': active_ips
        },
        'inactive_ips': {
            'count': len(inactive_ips),
            'percentage': 100 - active_percentage,
            'ips': inactive_ips
        }
    }
    
    if scan_info:
        summary.update(scan_info)
    
    return summary


def create_test_directories(test_name: str) -> Tuple[str, str]:
    """
    Create directories for storing test results.
    
    Args:
        test_name: Name of the test
        
    Returns:
        Tuple[str, str]: Paths to activeips and inactiveips directories
    """
    base_dir = os.path.join("output", test_name)
    active_dir = os.path.join(base_dir, "activeips")
    inactive_dir = os.path.join(base_dir, "inactiveips")
    
    # Create directories if they don't exist
    for directory in [active_dir, inactive_dir]:
        if not os.path.exists(directory):
            os.makedirs(directory)
    
    return active_dir, inactive_dir


def save_results_to_file(results: Dict[str, Any], file_path: str = None, format_type: str = 'json', test_name: str = None) -> str:
    """
    Save scan results to a file.
    
    Args:
        results: Scan results dictionary
        file_path: Path to save the file (if None, a default path will be generated)
        format_type: File format ('json', 'txt', or 'csv')
        test_name: Name of the test (if provided, results will be saved in test directories)
        
    Returns:
        str: Path to the saved file
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    if test_name:
        # Create test directories and save active/inactive IPs separately
        active_dir, inactive_dir = create_test_directories(test_name)
        
        # Save active IPs
        active_ips = results.get('active_ips', {}).get('ips', [])
        if active_ips:
            active_file = os.path.join(active_dir, f"active_ips_{timestamp}.{format_type}")
            save_ip_list(active_ips, active_file, format_type, "active")
        
        # Save inactive IPs
        inactive_ips = results.get('inactive_ips', {}).get('ips', [])
        if inactive_ips:
            inactive_file = os.path.join(inactive_dir, f"inactive_ips_{timestamp}.{format_type}")
            save_ip_list(inactive_ips, inactive_file, format_type, "inactive")
        
        # Save complete results to the base directory
        if file_path is None:
            file_path = os.path.join("output", test_name, f"scan_results_{timestamp}.{format_type}")
    elif file_path is None:
        file_path = f"scan_results_{timestamp}.{format_type}"
    
    directory = os.path.dirname(file_path)
    if directory and not os.path.exists(directory):
        os.makedirs(directory)
    
    if format_type == 'json':
        with open(file_path, 'w') as f:
            json.dump(results, f, indent=2)
    elif format_type == 'txt':
        with open(file_path, 'w') as f:
            active_ips = results.get('active_ips', {}).get('ips', [])
            inactive_ips = results.get('inactive_ips', {}).get('ips', [])
            f.write(format_scan_results(active_ips, inactive_ips, results))
    elif format_type == 'csv':
        with open(file_path, 'w') as f:
            f.write("IP,Status\n")
            for ip in results.get('active_ips', {}).get('ips', []):
                f.write(f"{ip},active\n")
            for ip in results.get('inactive_ips', {}).get('ips', []):
                f.write(f"{ip},inactive\n")
    else:
        raise ValueError(f"Unsupported format type: {format_type}")
    
    return file_path


def save_ip_list(ip_list: List[str], file_path: str, format_type: str, status: str) -> str:
    """
    Save a list of IPs to a file.
    
    Args:
        ip_list: List of IP addresses
        file_path: Path to save the file
        format_type: File format ('json', 'txt', or 'csv')
        status: Status of the IPs ('active' or 'inactive')
        
    Returns:
        str: Path to the saved file
    """
    directory = os.path.dirname(file_path)
    if directory and not os.path.exists(directory):
        os.makedirs(directory)
    
    if format_type == 'json':
        with open(file_path, 'w') as f:
            json.dump({"ips": ip_list, "status": status, "count": len(ip_list)}, f, indent=2)
    elif format_type == 'txt':
        with open(file_path, 'w') as f:
            f.write(f"{status.upper()} IPs ({len(ip_list)}):\n")
            for ip in ip_list:
                f.write(f"{ip}\n")
    elif format_type == 'csv':
        with open(file_path, 'w') as f:
            f.write("IP,Status\n")
            for ip in ip_list:
                f.write(f"{ip},{status}\n")
    else:
        raise ValueError(f"Unsupported format type: {format_type}")
    
    return file_path