"""
Network Scanner Module for ROCON Tools
Provides functionality for scanning IP addresses to determine if they are active.
"""
import socket
import subprocess
import platform
import struct
import json
import urllib.request
import urllib.error
from typing import List, Dict, Tuple, Set, Optional, Any, Union
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


def check_minecraft_server_api(ip: str, port: int = None, timeout: float = 10.0, retries: int = 2, verbose: bool = False) -> Dict[str, Any]:
    """
    Check if a specific IP and port is a Minecraft server using the mcsrvstat.us API.
    
    Args:
        ip: IP address or hostname to check
        port: Port to check (optional, the API will find it if not specified)
        timeout: Timeout in seconds for the API request
        retries: Number of retry attempts if the request fails
        verbose: Whether to print detailed information
        
    Returns:
        Dict[str, Any]: Dictionary with server information, including 'online' status
    """
    # Construct the API URL
    base_url = "https://api.mcsrvstat.us/3/"
    if port is not None:
        address = f"{ip}:{port}"
    else:
        address = ip
    
    url = base_url + address
    
    # Set up the request with a proper User-Agent
    headers = {
        "User-Agent": "ROCON-Scanner/1.0 (https://github.com/yourusername/rocon-ip-scanner)"
    }
    
    # Try multiple times in case of temporary failures
    for attempt in range(retries + 1):
        try:
            if verbose and attempt > 0:
                print(f"Retry attempt {attempt} for {ip}:{port}")
                
            # Create a request object with headers
            req = urllib.request.Request(url, headers=headers)
            
            # Open the URL with timeout
            with urllib.request.urlopen(req, timeout=timeout) as response:
                # Parse the JSON response
                data = json.loads(response.read().decode('utf-8'))
                
                if verbose:
                    if data.get("online", False):
                        print(f"Found Minecraft server at {ip}:{port} - Version: {data.get('version', 'Unknown')}")
                
                return data
        except urllib.error.HTTPError as e:
            # Handle HTTP errors (e.g., 403 Forbidden)
            error = f"HTTP Error: {e.code} {e.reason}"
            if verbose:
                print(f"API error for {ip}:{port} - {error}")
            
            # If it's a rate limiting error (429), wait longer before retrying
            if e.code == 429 and attempt < retries:
                wait_time = 5 * (attempt + 1)  # Exponential backoff
                if verbose:
                    print(f"Rate limited. Waiting {wait_time}s before retry...")
                time.sleep(wait_time)
                continue
                
            # If we've exhausted retries or it's not a retryable error, return error
            if attempt >= retries:
                return {"online": False, "error": error}
        except urllib.error.URLError as e:
            # Handle URL errors (e.g., connection timeout)
            error = f"URL Error: {e.reason}"
            if verbose:
                print(f"API error for {ip}:{port} - {error}")
            
            # Retry for timeout errors
            if "timeout" in str(e.reason).lower() and attempt < retries:
                wait_time = 2 * (attempt + 1)  # Exponential backoff
                if verbose:
                    print(f"Timeout. Waiting {wait_time}s before retry...")
                time.sleep(wait_time)
                continue
                
            if attempt >= retries:
                return {"online": False, "error": error}
        except json.JSONDecodeError:
            # Handle invalid JSON response
            error = "Invalid JSON response from API"
            if verbose:
                print(f"API error for {ip}:{port} - {error}")
            
            # This could be a temporary issue, retry
            if attempt < retries:
                time.sleep(2)
                continue
                
            if attempt >= retries:
                return {"online": False, "error": error}
        except Exception as e:
            # Handle any other exceptions
            error = f"Error: {str(e)}"
            if verbose:
                print(f"API error for {ip}:{port} - {error}")
            
            # Generic retry for other errors
            if attempt < retries:
                time.sleep(2)
                continue
                
            if attempt >= retries:
                return {"online": False, "error": error}
    
    # This should never be reached, but just in case
    return {"online": False, "error": "Unknown error occurred"}


def check_minecraft_server(ip: str, port: int, timeout: float = 2.0, 
                       skip_socket_check: bool = False, retries: int = 2, 
                       verbose: bool = False) -> Union[bool, Dict[str, Any]]:
    """
    Check if a specific IP and port is a Minecraft server.
    Uses the mcsrvstat.us API for reliable detection.
    
    Args:
        ip: IP address to check
        port: Port to check
        timeout: Timeout in seconds
        skip_socket_check: Whether to skip the socket check and directly use the API
        retries: Number of retry attempts for API calls
        verbose: Whether to print detailed information
        
    Returns:
        Union[bool, Dict[str, Any]]: True/False for backward compatibility or server info dictionary
    """
    # Skip socket check if requested (more reliable but slower)
    if not skip_socket_check:
        # First check if the port is open using a quick socket connection
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        try:
            if verbose:
                print(f"Checking if port {port} is open on {ip}...")
                
            result = sock.connect_ex((ip, port))
            if result != 0:
                if verbose:
                    print(f"Port {port} is closed on {ip}")
                return False
                
            if verbose:
                print(f"Port {port} is open on {ip}, checking if it's a Minecraft server...")
        except Exception as e:
            if verbose:
                print(f"Socket error for {ip}:{port} - {str(e)}")
            return False
        finally:
            sock.close()
    elif verbose:
        print(f"Skipping socket check for {ip}:{port}, directly using API...")
    
    # If the port is open or we're skipping the socket check, use the API
    server_info = check_minecraft_server_api(ip, port, timeout=timeout, retries=retries, verbose=verbose)
    
    # For backward compatibility, return True if the server is online
    if isinstance(server_info, dict) and server_info.get("online", False):
        return server_info
    
    return False


def scan_minecraft_ports(ip: str, port_range: Tuple[int, int] = (2048, 30000), 
                  max_workers: int = 20, timeout: float = 2.0, 
                  skip_socket_check: bool = False, retries: int = 2,
                  batch_size: int = 100, delay_between_batches: float = 1.0,
                  verbose: bool = False, progress_callback=None) -> Dict[int, Dict[str, Any]]:
    """
    Scan a range of ports on a single IP for Minecraft servers.
    
    Args:
        ip: IP address to scan
        port_range: Tuple of (start_port, end_port) to scan
        max_workers: Maximum number of concurrent workers
        timeout: Timeout in seconds for each port check
        skip_socket_check: Whether to skip socket check and directly use API
        retries: Number of retry attempts for API calls
        batch_size: Number of ports to scan in each batch
        delay_between_batches: Delay in seconds between batches
        verbose: Whether to print detailed information
        progress_callback: Optional callback function to report progress
                          Called with (current_port, ports_completed, total_ports)
        
    Returns:
        Dict[int, Dict[str, Any]]: Dictionary mapping ports to server information
    """
    start_port, end_port = port_range
    ports = list(range(start_port, end_port + 1))
    total_ports = len(ports)
    minecraft_servers = {}
    completed_ports = 0
    
    # If we have a callback, initialize with 0 progress
    if progress_callback:
        progress_callback(start_port, 0, total_ports)
    
    # Process ports in batches to avoid overwhelming the API
    for i in range(0, total_ports, batch_size):
        batch_ports = ports[i:i+batch_size]
        
        if verbose:
            print(f"Scanning batch of {len(batch_ports)} ports ({batch_ports[0]}-{batch_ports[-1]}) on {ip}")
        
        # Use a smaller number of workers for API calls to avoid rate limiting
        actual_max_workers = min(max_workers, len(batch_ports))
        
        with ThreadPoolExecutor(max_workers=actual_max_workers) as executor:
            # Submit tasks for this batch
            futures = {
                executor.submit(
                    check_minecraft_server, 
                    ip, 
                    port, 
                    timeout=timeout,
                    skip_socket_check=skip_socket_check,
                    retries=retries,
                    verbose=verbose
                ): port for port in batch_ports
            }
            
            # Process results as they complete
            for future in futures:
                port = futures[future]
                try:
                    result = future.result()
                    if result:
                        if isinstance(result, dict):
                            # Store the full server info
                            minecraft_servers[port] = result
                            if verbose:
                                print(f"✅ Found Minecraft server at {ip}:{port}")
                        else:
                            # For backward compatibility if result is just True
                            minecraft_servers[port] = {"online": True}
                            if verbose:
                                print(f"✅ Found Minecraft server at {ip}:{port} (limited info)")
                except Exception as e:
                    if verbose:
                        print(f"❌ Error checking {ip}:{port} - {str(e)}")
                
                # Update progress
                completed_ports += 1
                if progress_callback:
                    progress_callback(port, completed_ports, total_ports)
        
        # Add a delay between batches to avoid overwhelming the API
        if i + batch_size < total_ports and delay_between_batches > 0:
            if verbose:
                print(f"Waiting {delay_between_batches}s before next batch...")
            time.sleep(delay_between_batches)
    
    if verbose:
        print(f"Completed scan of {total_ports} ports on {ip}, found {len(minecraft_servers)} Minecraft servers")
    
    return minecraft_servers


def scan_minecraft_servers(ip_list: List[str], port_range: Tuple[int, int] = (2048, 30000), 
                       max_workers: int = 20, timeout: float = 2.0,
                       skip_socket_check: bool = False, retries: int = 2,
                       batch_size: int = 100, delay_between_batches: float = 1.0,
                       verbose: bool = False) -> Dict[str, Dict[int, Dict[str, Any]]]:
    """
    Scan multiple IPs for Minecraft servers.
    
    Args:
        ip_list: List of IP addresses to scan
        port_range: Tuple of (start_port, end_port) to scan
        max_workers: Maximum number of concurrent workers
        timeout: Timeout in seconds for each port check
        skip_socket_check: Whether to skip socket check and directly use API
        retries: Number of retry attempts for API calls
        batch_size: Number of ports to scan in each batch
        delay_between_batches: Delay in seconds between batches
        verbose: Whether to print detailed information
        
    Returns:
        Dict[str, Dict[int, Dict[str, Any]]]: Dictionary mapping IP addresses to dictionaries of port->server info
    """
    results = {}
    
    for ip in ip_list:
        if verbose:
            print(f"\nScanning IP: {ip} for Minecraft servers...")
            
        minecraft_servers = scan_minecraft_ports(
            ip, 
            port_range, 
            max_workers, 
            timeout,
            skip_socket_check,
            retries,
            batch_size,
            delay_between_batches,
            verbose
        )
        
        if minecraft_servers:
            results[ip] = minecraft_servers
            if verbose:
                print(f"Found {len(minecraft_servers)} Minecraft servers on {ip}")
        elif verbose:
            print(f"No Minecraft servers found on {ip}")
    
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


def scan_minecraft_servers_with_progress(ip_list: List[str], port_range: Tuple[int, int] = (2048, 30000), 
                                max_workers: int = 20, timeout: float = 2.0,
                                skip_socket_check: bool = False, retries: int = 2,
                                batch_size: int = 100, delay_between_batches: float = 1.0,
                                verbose: bool = False) -> Dict[str, Dict[int, Dict[str, Any]]]:
    """
    Scan multiple IPs for Minecraft servers with beautified live progress reporting.
    Shows progress bars for both IP scanning and port scanning of the current IP.
    Uses the mcsrvstat.us API for reliable Minecraft server detection.
    
    Args:
        ip_list: List of IP addresses to scan
        port_range: Tuple of (start_port, end_port) to scan
        max_workers: Maximum number of concurrent workers
        timeout: Timeout in seconds for each port check
        skip_socket_check: Whether to skip socket check and directly use API (more reliable but slower)
        retries: Number of retry attempts for API calls
        batch_size: Number of ports to scan in each batch
        delay_between_batches: Delay in seconds between batches to avoid API rate limiting
        verbose: Whether to print detailed debugging information
        
    Returns:
        Dict[str, Dict[int, Dict[str, Any]]]: Dictionary mapping IP addresses to dictionaries of port->server info
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
        minecraft_servers = scan_minecraft_ports(
            ip, 
            port_range, 
            max_workers, 
            timeout,
            skip_socket_check,
            retries,
            batch_size,
            delay_between_batches,
            verbose and not skip_socket_check,  # Only show verbose output if not already showing in progress display
            progress_callback=port_progress_callback
        )
        
        # Update results
        if minecraft_servers:
            results[ip] = minecraft_servers
            found_servers += 1
            
            # Format server information for display
            server_info = []
            for port, server_data in minecraft_servers.items():
                if isinstance(server_data, dict) and server_data.get("online", False):
                    # Extract useful information if available
                    version = server_data.get("version", "Unknown")
                    players = server_data.get("players", {})
                    player_count = f"{players.get('online', '?')}/{players.get('max', '?')}" if isinstance(players, dict) else "?"
                    
                    server_info.append(f"{port} (v:{version}, players:{player_count})")
                else:
                    server_info.append(f"{port}")
            
            status = f"Found Minecraft servers at ports: {', '.join(server_info)}"
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
        for ip, servers in results.items():
            print(f"  {BOLD}{ip}:{RESET}")
            for port, server_data in servers.items():
                if isinstance(server_data, dict) and server_data.get("online", False):
                    # Extract and display detailed server information
                    version = server_data.get("version", "Unknown")
                    motd = server_data.get("motd", {})
                    motd_text = motd.get("clean", ["No MOTD"])[0] if isinstance(motd, dict) and "clean" in motd and motd["clean"] else "No MOTD"
                    
                    players = server_data.get("players", {})
                    if isinstance(players, dict):
                        player_count = f"{players.get('online', '?')}/{players.get('max', '?')}"
                        player_list = players.get("list", [])
                        player_sample = ", ".join([p.get("name", "?") for p in player_list[:3]]) if player_list else "None"
                        if len(player_list) > 3:
                            player_sample += f" and {len(player_list) - 3} more"
                    else:
                        player_count = "?"
                        player_sample = "None"
                    
                    software = server_data.get("software", "Unknown")
                    
                    print(f"    {YELLOW}Port {port}:{RESET}")
                    print(f"      {CYAN}Version:{RESET} {version}")
                    print(f"      {CYAN}MOTD:{RESET} {motd_text}")
                    print(f"      {CYAN}Players:{RESET} {player_count} online ({player_sample})")
                    print(f"      {CYAN}Software:{RESET} {software}")
                else:
                    # Minimal information for servers without detailed data
                    print(f"    {YELLOW}Port {port}:{RESET} Minecraft server detected")
    
    return results