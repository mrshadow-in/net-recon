"""
Network Scanner Module for ROCON Tools
Provides functionality for scanning IP addresses to determine if they are active.
"""
import socket
import subprocess
import platform
import struct
import json
from typing import List, Dict, Tuple, Set, Optional
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


def check_minecraft_server(ip: str, port: int, timeout: float = 1.0) -> bool:
    """
    Check if a specific IP and port is a Minecraft server.
    
    Args:
        ip: IP address to check
        port: Port to check
        timeout: Timeout in seconds
        
    Returns:
        bool: True if a Minecraft server is detected, False otherwise
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    
    try:
        # First check if the port is open
        result = sock.connect_ex((ip, port))
        if result != 0:
            return False
        
        # Send handshake packet
        # Protocol version: -1 (ping)
        # Server address: ip
        # Server port: port
        # Next state: 1 (status)
        packet_id = 0x00  # Handshake packet ID
        protocol_version = -1
        server_address = ip
        server_port = port
        next_state = 1
        
        # Construct the packet
        packet = bytearray()
        packet.append(packet_id)
        
        # Add protocol version (VarInt)
        val = protocol_version
        while True:
            temp = val & 0x7F
            val >>= 7
            if val != 0:
                temp |= 0x80
            packet.append(temp)
            if val == 0:
                break
        
        # Add server address (String)
        packet.extend(len(server_address).to_bytes(1, byteorder='big'))
        packet.extend(server_address.encode('utf-8'))
        
        # Add server port (Unsigned Short)
        packet.extend(server_port.to_bytes(2, byteorder='big'))
        
        # Add next state (VarInt)
        val = next_state
        while True:
            temp = val & 0x7F
            val >>= 7
            if val != 0:
                temp |= 0x80
            packet.append(temp)
            if val == 0:
                break
        
        # Prepend packet length
        packet_length = len(packet)
        length_bytes = bytearray()
        val = packet_length
        while True:
            temp = val & 0x7F
            val >>= 7
            if val != 0:
                temp |= 0x80
            length_bytes.append(temp)
            if val == 0:
                break
        
        # Send the handshake packet
        sock.sendall(length_bytes + packet)
        
        # Send status request packet
        status_packet = bytearray([0x01, 0x00])
        sock.sendall(status_packet)
        
        # Receive response
        response = sock.recv(1024)
        
        # If we got a response, it's likely a Minecraft server
        return len(response) > 0
    except Exception:
        return False
    finally:
        sock.close()


def scan_minecraft_ports(ip: str, port_range: Tuple[int, int] = (2048, 30000), max_workers: int = 50, timeout: float = 0.5, 
                  progress_callback=None) -> List[int]:
    """
    Scan a range of ports on a single IP for Minecraft servers.
    
    Args:
        ip: IP address to scan
        port_range: Tuple of (start_port, end_port) to scan
        max_workers: Maximum number of concurrent workers
        timeout: Timeout in seconds for each port check
        progress_callback: Optional callback function to report progress
                          Called with (current_port, ports_completed, total_ports)
        
    Returns:
        List[int]: List of ports where Minecraft servers were detected
    """
    start_port, end_port = port_range
    ports = list(range(start_port, end_port + 1))
    total_ports = len(ports)
    minecraft_ports = []
    completed_ports = 0
    
    # If we have a callback, initialize with 0 progress
    if progress_callback:
        progress_callback(start_port, 0, total_ports)
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all tasks
        futures = {executor.submit(check_minecraft_server, ip, port, timeout): port for port in ports}
        
        # Process results as they complete
        for future in futures:
            port = futures[future]
            try:
                if future.result():
                    minecraft_ports.append(port)
            except Exception:
                pass
            
            # Update progress
            completed_ports += 1
            if progress_callback:
                progress_callback(port, completed_ports, total_ports)
    
    return minecraft_ports


def scan_minecraft_servers(ip_list: List[str], port_range: Tuple[int, int] = (2048, 30000), max_workers: int = 50, timeout: float = 0.5) -> Dict[str, List[int]]:
    """
    Scan multiple IPs for Minecraft servers.
    
    Args:
        ip_list: List of IP addresses to scan
        port_range: Tuple of (start_port, end_port) to scan
        max_workers: Maximum number of concurrent workers
        timeout: Timeout in seconds for each port check
        
    Returns:
        Dict[str, List[int]]: Dictionary mapping IP addresses to lists of ports where Minecraft servers were detected
    """
    results = {}
    
    for ip in ip_list:
        minecraft_ports = scan_minecraft_ports(ip, port_range, max_workers, timeout)
        if minecraft_ports:
            results[ip] = minecraft_ports
    
    return results


def render_progress_bar(progress: float, width: int = 40) -> str:
    """
    Render a text-based progress bar.
    
    Args:
        progress: Progress value between 0 and 1
        width: Width of the progress bar in characters
        
    Returns:
        str: Text representation of the progress bar
    """
    completed_width = int(width * progress)
    remaining_width = width - completed_width
    
    # Use block characters for a more solid-looking progress bar
    bar = '█' * completed_width + '░' * remaining_width
    
    # Add percentage display
    percentage = f"{progress * 100:.1f}%"
    
    return f"[{bar}] {percentage}"


def format_time(seconds: float) -> str:
    """
    Format time in seconds to a human-readable string.
    
    Args:
        seconds: Time in seconds
        
    Returns:
        str: Formatted time string (e.g., "2h 30m 45s" or "45.2s")
    """
    if seconds < 60:
        return f"{seconds:.1f}s"
    
    minutes, seconds = divmod(seconds, 60)
    if minutes < 60:
        return f"{int(minutes)}m {int(seconds)}s"
    
    hours, minutes = divmod(minutes, 60)
    return f"{int(hours)}h {int(minutes)}m {int(seconds)}s"


def scan_minecraft_servers_with_progress(ip_list: List[str], port_range: Tuple[int, int] = (2048, 30000), max_workers: int = 50, timeout: float = 0.5) -> Dict[str, List[int]]:
    """
    Scan multiple IPs for Minecraft servers with beautified live progress reporting.
    Shows progress bars for both IP scanning and port scanning of the current IP.
    
    Args:
        ip_list: List of IP addresses to scan
        port_range: Tuple of (start_port, end_port) to scan
        max_workers: Maximum number of concurrent workers
        timeout: Timeout in seconds for each port check
        
    Returns:
        Dict[str, List[int]]: Dictionary mapping IP addresses to lists of ports where Minecraft servers were detected
    """
    # ANSI color codes
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    RESET = '\033[0m'
    
    total_ips = len(ip_list)
    results = {}
    completed = 0
    found_servers = 0
    
    # Variables for port scanning progress
    current_port = 0
    ports_completed = 0
    total_ports = port_range[1] - port_range[0] + 1
    
    # Print header with fixed information
    print(f"{BOLD}╔══════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}║             ROCON MINECRAFT SERVER SCANNER                   ║{RESET}")
    print(f"{BOLD}╚══════════════════════════════════════════════════════════════╝{RESET}")
    print(f"{CYAN}• Target:{RESET} {total_ips} IP addresses")
    print(f"{CYAN}• Port Range:{RESET} {port_range[0]}-{port_range[1]} ({total_ports} ports per IP)")
    print(f"{CYAN}• Threads:{RESET} {max_workers} per IP")
    print()
    
    # Print initial progress display
    print(f"{BOLD}IP Scan Progress:{RESET}")
    print(render_progress_bar(0))
    print(f"{BOLD}Port Scan Progress:{RESET}")
    print(render_progress_bar(0))
    print(f"{YELLOW}Current IP:{RESET} Waiting to start...")
    print(f"{YELLOW}Current Port:{RESET} N/A")
    print(f"{YELLOW}Status:{RESET} Initializing...")
    print(f"{YELLOW}IP Stats:{RESET} 0/{total_ips} IPs completed (0%) | Elapsed: 0s | ETA: N/A")
    print(f"{YELLOW}Found Servers:{RESET} 0")
    
    start_time = time.time()
    
    # Function to update the progress display
    def update_display(current_ip: str, status: str, ip_elapsed: float = 0, port_info: Tuple[int, int, int] = None):
        nonlocal completed
        
        # Calculate IP progress metrics
        ip_progress = completed / total_ips if total_ips > 0 else 0
        elapsed = time.time() - start_time
        
        # Calculate port progress metrics if provided
        port_progress = 0
        current_port_display = "N/A"
        if port_info:
            current_port, ports_done, ports_total = port_info
            port_progress = ports_done / ports_total if ports_total > 0 else 0
            current_port_display = str(current_port)
        
        # Estimate time remaining
        if completed > 0:
            avg_time_per_ip = elapsed / completed
            eta = avg_time_per_ip * (total_ips - completed)
            eta_str = format_time(eta)
        else:
            eta_str = "N/A"
        
        # Clear the screen area for our progress display (9 lines)
        # Move cursor up 9 lines and clear each line completely
        print("\033[9A", end="")  # Move up 9 lines
        
        # Update IP progress bar (clear line completely before writing)
        print("\033[2K\r" + f"{BOLD}IP Scan Progress:{RESET}")
        print("\033[2K\r" + render_progress_bar(ip_progress))
        
        # Update Port progress bar
        print("\033[2K\r" + f"{BOLD}Port Scan Progress:{RESET}")
        print("\033[2K\r" + render_progress_bar(port_progress))
        
        # Update current IP, port and status with proper clearing
        status_color = GREEN if "Found" in status else (RED if "No" in status else YELLOW)
        print("\033[2K\r" + f"{YELLOW}Current IP:{RESET} {current_ip}")
        print("\033[2K\r" + f"{YELLOW}Current Port:{RESET} {current_port_display}")
        print("\033[2K\r" + f"{YELLOW}Status:{RESET} {status_color}{status}{RESET}")
        
        # Update statistics with proper clearing
        stats = f"{completed}/{total_ips} IPs completed ({ip_progress*100:.1f}%) | "
        stats += f"Elapsed: {format_time(elapsed)} | ETA: {eta_str}"
        if ip_elapsed > 0:
            stats += f" | Current IP: {format_time(ip_elapsed)}"
        
        print("\033[2K\r" + f"{YELLOW}IP Stats:{RESET} {stats}")
        print("\033[2K\r" + f"{YELLOW}Found Servers:{RESET} {found_servers}")
    
    # Port progress callback function
    def port_progress_callback(port, completed_ports, total_ports):
        nonlocal current_port, ports_completed
        current_port = port
        ports_completed = completed_ports
        # Update the display with the current port progress
        update_display(
            current_ip=ip_list[completed] if completed < len(ip_list) else "Completed", 
            status=f"Scanning port {port} ({completed_ports}/{total_ports})",
            port_info=(port, completed_ports, total_ports)
        )
    
    # Scan each IP address
    for ip in ip_list:
        ip_start_time = time.time()
        
        # Reset port progress for new IP
        current_port = port_range[0]
        ports_completed = 0
        
        # Update display to show we're starting to scan this IP
        update_display(
            current_ip=ip, 
            status=f"Starting scan of ports {port_range[0]}-{port_range[1]}...",
            port_info=(current_port, 0, total_ports)
        )
        
        # Scan the IP for Minecraft servers with progress reporting
        minecraft_ports = scan_minecraft_ports(
            ip, port_range, max_workers, timeout, 
            progress_callback=port_progress_callback
        )
        
        # Update results
        if minecraft_ports:
            results[ip] = minecraft_ports
            found_servers += 1
            status = f"Found Minecraft servers at ports: {', '.join(map(str, minecraft_ports))}"
        else:
            status = "No Minecraft servers found"
        
        # Update completion count and display
        completed += 1
        ip_elapsed = time.time() - ip_start_time
        update_display(
            current_ip=ip, 
            status=status, 
            ip_elapsed=ip_elapsed,
            port_info=(current_port, total_ports, total_ports)  # Show completed port scan
        )
    
    # Final update with summary
    total_time = time.time() - start_time
    
    # Print summary footer
    print("\n")
    print(f"{BOLD}╔══════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}║                      SCAN COMPLETED                          ║{RESET}")
    print(f"{BOLD}╚══════════════════════════════════════════════════════════════╝{RESET}")
    print(f"{CYAN}• Total Time:{RESET} {format_time(total_time)}")
    print(f"{CYAN}• IPs Scanned:{RESET} {total_ips}")
    print(f"{CYAN}• Minecraft Servers Found:{RESET} {found_servers}")
    if found_servers > 0:
        print(f"\n{GREEN}Minecraft Servers:{RESET}")
        for ip, ports in results.items():
            print(f"  {BOLD}{ip}:{RESET} {', '.join(map(str, ports))}")
    
    return results