"""
Network Scanner Module for ROCON Tools
Provides functionality for scanning IP addresses to determine if they are active.
"""
import socket
import subprocess
import platform
from typing import List, Dict, Tuple
from concurrent.futures import ThreadPoolExecutor
import time


def ping_ip(ip: str, timeout: float = 1.0) -> bool:
    """
    Check if an IP address is active using ping.
    
    Args:
        ip: IP address to ping
        timeout: Timeout in seconds
        
    Returns:
        bool: True if IP is active, False otherwise
    """
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, '1', '-w', str(int(timeout * 1000)), ip]
    
    try:
        return subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0
    except Exception:
        return False


def socket_check(ip: str, port: int = 80, timeout: float = 1.0) -> bool:
    """
    Check if an IP address is active by attempting to connect to a specific port.
    
    Args:
        ip: IP address to check
        port: Port to connect to
        timeout: Timeout in seconds
        
    Returns:
        bool: True if connection successful, False otherwise
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    
    try:
        result = sock.connect_ex((ip, port))
        return result == 0
    except Exception:
        return False
    finally:
        sock.close()


def scan_ips(ip_list: List[str], method: str = 'ping', max_workers: int = 50) -> Dict[str, bool]:
    """
    Scan a list of IP addresses to determine which ones are active.
    
    Args:
        ip_list: List of IP addresses to scan
        method: Scanning method ('ping' or 'socket')
        max_workers: Maximum number of concurrent workers
        
    Returns:
        Dict[str, bool]: Dictionary mapping IP addresses to their active status
    """
    results = {}
    
    # Use ThreadPoolExecutor for parallel scanning
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        if method == 'ping':
            futures = {executor.submit(ping_ip, ip): ip for ip in ip_list}
        elif method == 'socket':
            futures = {executor.submit(socket_check, ip): ip for ip in ip_list}
        else:
            raise ValueError(f"Invalid scanning method: {method}")
        
        for future in futures:
            ip = futures[future]
            try:
                results[ip] = future.result()
            except Exception:
                results[ip] = False
    
    return results


def get_active_inactive_ips(scan_results: Dict[str, bool]) -> Tuple[List[str], List[str]]:
    """
    Separate scan results into active and inactive IP lists.
    
    Args:
        scan_results: Dictionary mapping IP addresses to their active status
        
    Returns:
        Tuple[List[str], List[str]]: Tuple containing (active_ips, inactive_ips)
    """
    active_ips = [ip for ip, status in scan_results.items() if status]
    inactive_ips = [ip for ip, status in scan_results.items() if not status]
    
    return active_ips, inactive_ips


def scan_with_progress(ip_list: List[str], method: str = 'ping', max_workers: int = 50) -> Dict[str, bool]:
    """
    Scan a list of IP addresses with progress reporting.
    
    Args:
        ip_list: List of IP addresses to scan
        method: Scanning method ('ping' or 'socket')
        max_workers: Maximum number of concurrent workers
        
    Returns:
        Dict[str, bool]: Dictionary mapping IP addresses to their active status
    """
    total_ips = len(ip_list)
    results = {}
    completed = 0
    
    print(f"Starting scan of {total_ips} IP addresses...")
    start_time = time.time()
    
    # Process IPs in batches to show progress
    batch_size = max(1, min(max_workers, total_ips // 10))
    for i in range(0, total_ips, batch_size):
        batch = ip_list[i:i+batch_size]
        batch_results = scan_ips(batch, method, max_workers)
        results.update(batch_results)
        
        completed += len(batch)
        progress = (completed / total_ips) * 100
        elapsed = time.time() - start_time
        
        print(f"Progress: {completed}/{total_ips} IPs scanned ({progress:.1f}%) - Time elapsed: {elapsed:.1f}s")
    
    total_time = time.time() - start_time
    print(f"Scan completed in {total_time:.2f} seconds.")
    
    return results