"""
Output Formatter Module for ROCON Tools
Provides functionality for formatting and displaying scan results in a beautified manner.
"""
from typing import List, Dict, Any
import json
from datetime import datetime
import os


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


def save_results_to_file(results: Dict[str, Any], file_path: str = None, format_type: str = 'json') -> str:
    """
    Save scan results to a file.
    
    Args:
        results: Scan results dictionary
        file_path: Path to save the file (if None, a default path will be generated)
        format_type: File format ('json', 'txt', or 'csv')
        
    Returns:
        str: Path to the saved file
    """
    if file_path is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
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