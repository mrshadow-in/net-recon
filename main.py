#!/usr/bin/env python3
"""
ROCON IP Scanner Tool

A CLI tool for scanning IP ranges or subnets to identify active and inactive IP addresses.
"""
import argparse
import sys
import time
import os
from typing import Dict, List, Tuple, Optional, Any

from ip_utils import validate_ip, validate_subnet, parse_ip_input
from network_scanner import scan_with_progress, get_active_inactive_ips, scan_minecraft_servers_with_progress, scan_ports_with_progress, scan_ports_from_file
from output_formatter import format_scan_results, get_results_summary, save_results_to_file, create_test_directories


def parse_arguments() -> argparse.Namespace:
    """
    Parse command-line arguments.
    
    Returns:
        argparse.Namespace: Parsed command-line arguments
    """
    parser = argparse.ArgumentParser(
        description="ROCON IP Scanner - Scan IP ranges or subnets for active hosts",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    # IP input options (mutually exclusive)
    ip_group = parser.add_mutually_exclusive_group(required=True)
    ip_group.add_argument(
        "--range", "-r", nargs=2, metavar=("START_IP", "END_IP"),
        help="Specify an IP range to scan (e.g., 192.168.1.1 192.168.1.254)"
    )
    ip_group.add_argument(
        "--subnet", "-s", metavar="SUBNET",
        help="Specify a subnet to scan in CIDR notation (e.g., 192.168.1.0/24)"
    )
    
    # Scan options
    scan_group = parser.add_argument_group("Scan Options")
    scan_group.add_argument(
        "--method", "-m", choices=["ping", "socket"], default="ping",
        help="Method to use for scanning (ping or socket)"
    )
    scan_group.add_argument(
        "--workers", "-w", type=int, default=50,
        help="Maximum number of concurrent workers for scanning"
    )
    
    # Output options
    output_group = parser.add_argument_group("Output Options")
    output_group.add_argument(
        "--output", "-o", metavar="FILE",
        help="Save results to a file (default: scan_results_TIMESTAMP.json)"
    )
    output_group.add_argument(
        "--format", "-f", choices=["json", "txt", "csv"], default="json",
        help="Format for saving results"
    )
    output_group.add_argument(
        "--no-color", action="store_true",
        help="Disable colored output in the console"
    )
    output_group.add_argument(
        "--verbose", "-v", action="store_true",
        help="Enable verbose output with detailed information"
    )
    
    return parser.parse_args()


def get_scan_mode() -> str:
    """
    Get the scan mode from the user.
    
    Returns:
        str: Scan mode ('ip', 'port', or 'minecraft')
    """
    print("ROCON Scanner - Select Mode")
    print("===========================")
    print("1. IP Scanner (Ping/Socket)")
    print("2. Port Scanner (TCP/UDP)")
    print("3. Minecraft Port Scanner")
    
    while True:
        choice = input("\nEnter your choice (1, 2, or 3): ").strip()
        if choice == '1':
            return 'ip'
        elif choice == '2':
            return 'port'
        elif choice == '3':
            return 'minecraft'
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")


def get_user_input() -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str], bool]:
    """
    Get IP range or subnet input from the user interactively for IP scanning.
    
    Returns:
        Tuple[Optional[str], Optional[str], Optional[str], Optional[str], bool]: (start_ip, end_ip, subnet, test_name, verbose)
    """
    print("\nROCON IP Scanner - Interactive Mode")
    print("===================================")
    
    # Get test name
    test_name = input("Name of Test: ").strip()
    
    # Get verbose option
    verbose_input = input("Enable verbose output with detailed information? (y/n, default: n): ").strip().lower()
    verbose = verbose_input and verbose_input[0] == 'y'
    
    print("\nPlease enter either an IP range or a subnet to scan.")
    print("Leave blank and press Enter to skip an input method.\n")
    
    # Get IP range input
    start_ip = input("Start IP (e.g., 192.168.1.1): ").strip()
    end_ip = input("End IP (e.g., 192.168.1.254): ").strip() if start_ip else ""
    
    # Validate IP range if provided
    if start_ip and end_ip:
        if not validate_ip(start_ip):
            print(f"Error: Invalid start IP address: {start_ip}")
            start_ip = end_ip = None
        elif not validate_ip(end_ip):
            print(f"Error: Invalid end IP address: {end_ip}")
            start_ip = end_ip = None
    else:
        start_ip = end_ip = None
    
    # Get subnet input if IP range not provided
    subnet = None
    if not start_ip and not end_ip:
        subnet = input("Subnet (e.g., 192.168.1.0/24): ").strip()
        if subnet and not validate_subnet(subnet):
            print(f"Error: Invalid subnet: {subnet}")
            subnet = None
    
    return start_ip, end_ip, subnet, test_name, verbose


def get_minecraft_scan_input() -> Tuple[Optional[str], Optional[str], Optional[str], int, Tuple[int, int], float, bool, int, int, float, bool, Optional[str]]:
    """
    Get input for Minecraft server scanning.
    
    Returns:
        Tuple containing:
            - start_ip (Optional[str]): Starting IP address
            - end_ip (Optional[str]): Ending IP address
            - subnet (Optional[str]): Subnet in CIDR notation
            - threads (int): Number of concurrent threads to use
            - port_range (Tuple[int, int]): Range of ports to scan
            - timeout (float): Timeout in seconds for each port check
            - skip_socket_check (bool): Whether to skip socket check and directly use API
            - retries (int): Number of retry attempts for API calls
            - batch_size (int): Number of ports to scan in each batch
            - delay_between_batches (float): Delay in seconds between batches
            - verbose (bool): Whether to print detailed information
            - test_name (Optional[str]): Name of the test
    """
    print("\nROCON Minecraft Scanner - Interactive Mode")
    print("=========================================")
    
    # Get test name
    test_name = input("Name of Test: ").strip()
    
    # Get verbose option
    verbose_input = input("Enable verbose output with detailed information? (y/n, default: n): ").strip().lower()
    verbose = verbose_input and verbose_input[0] == 'y'
    
    if verbose:
        print("\nVerbose mode enabled. Detailed information will be displayed during scanning.")
    
    print("\nPlease enter either an IP range or a subnet to scan for Minecraft servers.")
    print("Leave blank and press Enter to skip an input method.\n")
    
    # Get IP range input
    start_ip = input("Start IP (e.g., 192.168.1.1): ").strip()
    end_ip = input("End IP (e.g., 192.168.1.254): ").strip() if start_ip else ""
    
    # Validate IP range if provided
    if start_ip and end_ip:
        if not validate_ip(start_ip):
            print(f"Error: Invalid start IP address: {start_ip}")
            start_ip = end_ip = None
        elif not validate_ip(end_ip):
            print(f"Error: Invalid end IP address: {end_ip}")
            start_ip = end_ip = None
    else:
        start_ip = end_ip = None
    
    # Get subnet input if IP range not provided
    subnet = None
    if not start_ip and not end_ip:
        subnet = input("Subnet (e.g., 192.168.1.0/24): ").strip()
        if subnet and not validate_subnet(subnet):
            print(f"Error: Invalid subnet: {subnet}")
            subnet = None
    
    # Get port range
    default_start_port = 2048
    default_end_port = 30000
    print(f"\nEnter port range to scan (default: {default_start_port}-{default_end_port}):")
    
    # Get start port
    start_port = default_start_port
    start_port_input = input(f"Start port (default: {default_start_port}): ").strip()
    if start_port_input:
        try:
            start_port = int(start_port_input)
            if start_port < 1 or start_port > 65535:
                print(f"Start port must be between 1 and 65535. Using default value: {default_start_port}.")
                start_port = default_start_port
        except ValueError:
            print(f"Invalid start port. Using default value: {default_start_port}.")
    
    # Get end port
    end_port = default_end_port
    end_port_input = input(f"End port (default: {default_end_port}): ").strip()
    if end_port_input:
        try:
            end_port = int(end_port_input)
            if end_port < 1 or end_port > 65535:
                print(f"End port must be between 1 and 65535. Using default value: {default_end_port}.")
                end_port = default_end_port
        except ValueError:
            print(f"Invalid end port. Using default value: {default_end_port}.")
    
    # Ensure start_port <= end_port
    if start_port > end_port:
        print(f"Start port ({start_port}) is greater than end port ({end_port}). Swapping values.")
        start_port, end_port = end_port, start_port
    
    # Get number of threads
    threads = 20  # Default value
    threads_input = input(f"\nNumber of threads to use (default: {threads}): ").strip()
    if threads_input:
        try:
            threads = int(threads_input)
            if threads < 1:
                print("Number of threads must be at least 1. Using default value.")
                threads = 20
        except ValueError:
            print("Invalid number of threads. Using default value.")
    
    # Get timeout
    timeout = 2.0  # Default value
    timeout_input = input(f"\nTimeout in seconds for each port check (default: {timeout}): ").strip()
    if timeout_input:
        try:
            timeout = float(timeout_input)
            if timeout <= 0:
                print("Timeout must be greater than 0. Using default value.")
                timeout = 2.0
        except ValueError:
            print("Invalid timeout. Using default value.")
    
    # Get advanced options
    print("\nAdvanced Options (press Enter to use defaults):")
    
    # Skip socket check option
    skip_socket_check = False  # Default value
    skip_socket_input = input("Skip socket check and directly use API? This is more reliable but slower (y/n, default: n): ").strip().lower()
    if skip_socket_input and skip_socket_input[0] == 'y':
        skip_socket_check = True
        print("Socket check will be skipped. API will be used directly for all ports.")
    
    # Get retries
    retries = 2  # Default value
    retries_input = input(f"Number of retry attempts for API calls (default: {retries}): ").strip()
    if retries_input:
        try:
            retries = int(retries_input)
            if retries < 0:
                print("Retries must be non-negative. Using default value.")
                retries = 2
        except ValueError:
            print("Invalid retries. Using default value.")
    
    # Get batch size
    batch_size = 100  # Default value
    batch_size_input = input(f"Number of ports to scan in each batch (default: {batch_size}): ").strip()
    if batch_size_input:
        try:
            batch_size = int(batch_size_input)
            if batch_size < 1:
                print("Batch size must be at least 1. Using default value.")
                batch_size = 100
        except ValueError:
            print("Invalid batch size. Using default value.")
    
    # Get delay between batches
    delay = 1.0  # Default value
    delay_input = input(f"Delay in seconds between batches (default: {delay}): ").strip()
    if delay_input:
        try:
            delay = float(delay_input)
            if delay < 0:
                print("Delay must be non-negative. Using default value.")
                delay = 1.0
        except ValueError:
            print("Invalid delay. Using default value.")
    
    # Get verbose option
    verbose = False  # Default value
    verbose_input = input("Show detailed debugging information? (y/n, default: n): ").strip().lower()
    if verbose_input and verbose_input[0] == 'y':
        verbose = True
        print("Verbose mode enabled. Detailed debugging information will be shown.")
    
    return start_ip, end_ip, subnet, threads, (start_port, end_port), timeout, skip_socket_check, retries, batch_size, delay, verbose, test_name


def get_port_scan_input() -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str], int, Tuple[int, int], List[str], float, Optional[str], bool]:
    """
    Get input for port scanning.
    
    Returns:
        Tuple containing:
            - start_ip (Optional[str]): Starting IP address
            - end_ip (Optional[str]): Ending IP address
            - subnet (Optional[str]): Subnet in CIDR notation
            - scan_file (Optional[str]): Path to a previous scan result file to load active IPs from
            - threads (int): Number of concurrent threads to use
            - port_range (Tuple[int, int]): Range of ports to scan
            - protocols (List[str]): List of protocols to scan ('tcp', 'udp', or both)
            - timeout (float): Timeout in seconds for each port check
            - test_name (Optional[str]): Name of the test
            - verbose (bool): Whether to print detailed information
    """
    print("\nROCON Port Scanner - Interactive Mode")
    print("====================================")
    
    # Get test name
    test_name = input("Name of Test: ").strip()
    
    # Get verbose option
    verbose_input = input("Enable verbose output with detailed information? (y/n, default: n): ").strip().lower()
    verbose = verbose_input and verbose_input[0] == 'y'
    
    if verbose:
        print("\nVerbose mode enabled. Detailed information will be displayed during scanning.")
    
    print("\nPlease select an IP input method:")
    print("1. IP Range")
    print("2. Subnet")
    print("3. Load active IPs from previous scan")
    
    input_method = input("\nEnter your choice (1, 2, or 3): ").strip()
    
    start_ip = end_ip = subnet = scan_file = None
    
    # Handle IP range input
    if input_method == '1':
        print("\nPlease enter an IP range to scan.")
        start_ip = input("Start IP (e.g., 192.168.1.1): ").strip()
        end_ip = input("End IP (e.g., 192.168.1.254): ").strip() if start_ip else ""
        
        # Validate IP range
        if start_ip and end_ip:
            if not validate_ip(start_ip):
                print(f"Error: Invalid start IP address: {start_ip}")
                start_ip = end_ip = None
            elif not validate_ip(end_ip):
                print(f"Error: Invalid end IP address: {end_ip}")
                start_ip = end_ip = None
        else:
            start_ip = end_ip = None
    
    # Handle subnet input
    elif input_method == '2':
        print("\nPlease enter a subnet to scan.")
        subnet = input("Subnet (e.g., 192.168.1.0/24): ").strip()
        if subnet and not validate_subnet(subnet):
            print(f"Error: Invalid subnet: {subnet}")
            subnet = None
    
    # Handle loading from previous scan
    elif input_method == '3':
        print("\nPlease enter the path to a previous scan result file.")
        scan_file = input("File path: ").strip()
        if not scan_file or not os.path.exists(scan_file):
            print(f"Error: File not found: {scan_file}")
            scan_file = None
    
    else:
        print("Invalid choice. Please restart and select a valid option.")
    
    # Get port range
    default_start_port = 1
    default_end_port = 1024
    print(f"\nEnter port range to scan (default: {default_start_port}-{default_end_port}):")
    
    # Get start port
    start_port = default_start_port
    start_port_input = input(f"Start port (default: {default_start_port}): ").strip()
    if start_port_input:
        try:
            start_port = int(start_port_input)
            if start_port < 1 or start_port > 65535:
                print(f"Start port must be between 1 and 65535. Using default value: {default_start_port}.")
                start_port = default_start_port
        except ValueError:
            print(f"Invalid start port. Using default value: {default_start_port}.")
    
    # Get end port
    end_port = default_end_port
    end_port_input = input(f"End port (default: {default_end_port}): ").strip()
    if end_port_input:
        try:
            end_port = int(end_port_input)
            if end_port < 1 or end_port > 65535:
                print(f"End port must be between 1 and 65535. Using default value: {default_end_port}.")
                end_port = default_end_port
        except ValueError:
            print(f"Invalid end port. Using default value: {default_end_port}.")
    
    # Ensure start_port <= end_port
    if start_port > end_port:
        print(f"Start port ({start_port}) is greater than end port ({end_port}). Swapping values.")
        start_port, end_port = end_port, start_port
    
    # Get protocols to scan
    protocols = ['tcp', 'udp']  # Default value
    protocol_input = input("\nProtocols to scan (tcp, udp, or both; default: both): ").strip().lower()
    if protocol_input:
        if protocol_input == 'tcp':
            protocols = ['tcp']
        elif protocol_input == 'udp':
            protocols = ['udp']
        elif protocol_input == 'both':
            protocols = ['tcp', 'udp']
        else:
            print("Invalid protocol selection. Using default value (both).")
    
    # Get number of threads
    threads = 50  # Default value
    threads_input = input(f"\nNumber of threads to use (default: {threads}): ").strip()
    if threads_input:
        try:
            threads = int(threads_input)
            if threads < 1:
                print("Number of threads must be at least 1. Using default value.")
                threads = 50
        except ValueError:
            print("Invalid number of threads. Using default value.")
    
    # Get timeout
    timeout = 1.0  # Default value
    timeout_input = input(f"\nTimeout in seconds for each port check (default: {timeout}): ").strip()
    if timeout_input:
        try:
            timeout = float(timeout_input)
            if timeout <= 0:
                print("Timeout must be greater than 0. Using default value.")
                timeout = 1.0
        except ValueError:
            print("Invalid timeout. Using default value.")
    
    return start_ip, end_ip, subnet, scan_file, threads, (start_port, end_port), protocols, timeout, test_name, verbose


def run_scan(ip_list: List[str], method: str = "ping", max_workers: int = 50, verbose: bool = False) -> Dict:
    """
    Run the IP scan and return the results.
    
    Args:
        ip_list: List of IP addresses to scan
        method: Scanning method ('ping' or 'socket')
        max_workers: Maximum number of concurrent workers
        verbose: Whether to print detailed information
        
    Returns:
        Dict: Scan results summary
    """
    start_time = time.time()
    
    # Run the scan with progress reporting
    scan_results = scan_with_progress(ip_list, method, max_workers, verbose)
    
    # Get active and inactive IPs
    active_ips, inactive_ips = get_active_inactive_ips(scan_results)
    
    # Create scan info
    scan_duration = time.time() - start_time
    scan_info = {
        'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),
        'duration': scan_duration,
        'scan_method': method,
        'total_ips': len(ip_list)
    }
    
    # Get results summary
    results_summary = get_results_summary(active_ips, inactive_ips, scan_info)
    
    return results_summary


def run_port_scan(ip_list: List[str] = None, scan_file: str = None, port_range: Tuple[int, int] = (1, 1024),
                protocols: List[str] = ['tcp', 'udp'], timeout: float = 1.0,
                max_workers: int = 50, verbose: bool = False) -> Dict[str, Any]:
    """
    Run the port scan and return the results.
    
    Args:
        ip_list: List of IP addresses to scan (optional if scan_file is provided)
        scan_file: Path to a previous scan result file to load active IPs from (optional if ip_list is provided)
        port_range: Tuple of (start_port, end_port) to scan
        protocols: List of protocols to scan ('tcp', 'udp', or both)
        timeout: Timeout in seconds for each port check
        max_workers: Maximum number of concurrent workers
        verbose: Whether to print detailed information
        
    Returns:
        Dict[str, Any]: Port scan results with detailed information about open ports
    """
    start_time = time.time()
    
    # Run the port scan with progress reporting
    if scan_file:
        # Load active IPs from a previous scan result file
        port_results = scan_ports_from_file(scan_file, port_range, protocols, timeout, max_workers, verbose)
    else:
        # Scan the provided IP list
        port_results = scan_ports_with_progress(ip_list, port_range, protocols, timeout, max_workers, verbose)
    
    # Create scan info
    scan_duration = time.time() - start_time
    
    # Count open ports
    total_open_tcp = sum(len(port_results[ip]['tcp']) for ip in port_results)
    total_open_udp = sum(len(port_results[ip]['udp']) for ip in port_results)
    total_open = total_open_tcp + total_open_udp
    
    # Format results
    results = {
        'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),
        'duration': scan_duration,
        'scan_method': 'port',
        'port_range': list(port_range),  # Convert tuple to list for JSON compatibility
        'protocols': protocols,
        'total_ips': len(port_results),
        'open_ports': {
            'count': total_open,
            'tcp_count': total_open_tcp,
            'udp_count': total_open_udp,
            'by_ip': port_results
        }
    }
    
    return results


def run_minecraft_scan(ip_list: List[str], max_workers: int = 20, port_range: Tuple[int, int] = (2048, 30000),
                  timeout: float = 2.0, skip_socket_check: bool = False, retries: int = 2,
                  batch_size: int = 100, delay_between_batches: float = 1.0,
                  verbose: bool = False) -> Dict[str, Any]:
    """
    Run the Minecraft server scan and return the results.
    Uses the mcsrvstat.us API for reliable Minecraft server detection.
    
    Args:
        ip_list: List of IP addresses to scan
        max_workers: Maximum number of concurrent workers
        port_range: Tuple of (start_port, end_port) to scan
        timeout: Timeout in seconds for each port check
        skip_socket_check: Whether to skip socket check and directly use API (more reliable but slower)
        retries: Number of retry attempts for API calls
        batch_size: Number of ports to scan in each batch
        delay_between_batches: Delay in seconds between batches to avoid API rate limiting
        verbose: Whether to print detailed debugging information
        
    Returns:
        Dict[str, Any]: Minecraft scan results with detailed server information
                        including version, player count, MOTD, and other server details
    """
    start_time = time.time()
    
    # Run the Minecraft scan with progress reporting
    minecraft_results = scan_minecraft_servers_with_progress(
        ip_list, 
        port_range, 
        max_workers,
        timeout,
        skip_socket_check,
        retries,
        batch_size,
        delay_between_batches,
        verbose
    )
    
    # Create scan info
    scan_duration = time.time() - start_time
    
    # Format results
    results = {
        'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),
        'duration': scan_duration,
        'scan_method': 'minecraft',
        'port_range': list(port_range),  # Convert tuple to list for JSON compatibility
        'total_ips': len(ip_list),
        'minecraft_servers': {
            'count': len(minecraft_results),
            'percentage': (len(minecraft_results) / len(ip_list) * 100) if ip_list else 0,
            'servers': minecraft_results
        }
    }
    
    return results


def format_minecraft_results(minecraft_results: Dict[str, Dict[int, Dict[str, Any]]]) -> str:
    """
    Format Minecraft scan results for console display.
    Includes detailed server information from the mcsrvstat.us API.
    
    Args:
        minecraft_results: Dictionary mapping IP addresses to dictionaries of port->server info
        
    Returns:
        str: Formatted string representation of the Minecraft scan results with detailed server information
    """
    # Create a horizontal line for separation
    separator = "=" * 80
    
    # Format header
    header = ["ROCON MINECRAFT SCANNER - SCAN RESULTS", separator]
    
    # Format server list
    if minecraft_results:
        server_count = len(minecraft_results)
        total_ports = sum(len(ports) for ports in minecraft_results.values())
        server_section = [f"MINECRAFT SERVERS FOUND: {server_count} IPs with {total_ports} server ports"]
        
        for ip, servers in minecraft_results.items():
            server_section.append(f"\n  IP: {ip}")
            
            for port, server_data in servers.items():
                # Basic port information
                server_section.append(f"    Port: {port}")
                
                # Extract and display detailed server information if available
                if isinstance(server_data, dict) and server_data.get("online", False):
                    # Version information
                    version = server_data.get("version", "Unknown")
                    server_section.append(f"      Version: {version}")
                    
                    # MOTD (Message of the Day)
                    motd = server_data.get("motd", {})
                    if isinstance(motd, dict) and "clean" in motd and motd["clean"]:
                        motd_lines = motd["clean"]
                        for i, line in enumerate(motd_lines):
                            prefix = "      MOTD: " if i == 0 else "           "
                            server_section.append(f"{prefix}{line}")
                    
                    # Player information
                    players = server_data.get("players", {})
                    if isinstance(players, dict):
                        online = players.get("online", "?")
                        max_players = players.get("max", "?")
                        server_section.append(f"      Players: {online}/{max_players}")
                        
                        # List some players if available
                        player_list = players.get("list", [])
                        if player_list:
                            player_names = [p.get("name", "?") for p in player_list[:5]]
                            if len(player_list) > 5:
                                player_names.append(f"and {len(player_list) - 5} more")
                            server_section.append(f"      Online: {', '.join(player_names)}")
                    
                    # Software information
                    software = server_data.get("software", "")
                    if software:
                        server_section.append(f"      Software: {software}")
                    
                    # Additional information
                    if "hostname" in server_data:
                        server_section.append(f"      Hostname: {server_data['hostname']}")
                else:
                    server_section.append(f"      Status: Minecraft server detected (limited information)")
    else:
        server_section = ["NO MINECRAFT SERVERS FOUND"]
    
    # Combine all sections
    sections = header + [""] + server_section + ["", separator]
    sections.append("Note: Server information provided by mcsrvstat.us API")
    
    return "\n".join(sections)


def main():
    """
    Main function for the ROCON Scanner tool.
    """
    # Check if any command-line arguments were provided
    if len(sys.argv) > 1:
        # Parse command-line arguments
        args = parse_arguments()
        
        # Get IP list from arguments
        if args.range:
            start_ip, end_ip = args.range
            ip_list = parse_ip_input(start_ip=start_ip, end_ip=end_ip)
        else:  # args.subnet
            ip_list = parse_ip_input(subnet=args.subnet)
            
        # Command-line mode only supports IP scanning for now
        scan_mode = 'ip'
        test_name = None
        max_workers = args.workers
    else:
        # Interactive mode - Ask for scan mode
        scan_mode = get_scan_mode()
        
        if scan_mode == 'ip':
            # IP Scanner mode
            start_ip, end_ip, subnet, test_name, verbose = get_user_input()
            
            # Exit if no valid input
            if not start_ip and not end_ip and not subnet:
                print("Error: No valid IP range or subnet provided. Exiting.")
                sys.exit(1)
            
            # Get IP list from user input
            try:
                ip_list = parse_ip_input(start_ip=start_ip, end_ip=end_ip, subnet=subnet)
            except ValueError as e:
                print(f"Error: {e}")
                sys.exit(1)
            
            # Use default values for interactive mode
            args = argparse.Namespace(
                method="ping",
                workers=50,
                output=None,
                format="json",
                no_color=False,
                test_name=test_name,
                verbose=verbose
            )
            max_workers = args.workers
        elif scan_mode == 'port':
            # Port Scanner mode
            start_ip, end_ip, subnet, scan_file, threads, port_range, protocols, timeout, test_name, verbose = get_port_scan_input()
            
            # Check if we have valid input
            if not start_ip and not end_ip and not subnet and not scan_file:
                print("Error: No valid IP range, subnet, or scan file provided. Exiting.")
                sys.exit(1)
            
            # Get IP list from user input if not using a scan file
            if not scan_file:
                try:
                    ip_list = parse_ip_input(start_ip=start_ip, end_ip=end_ip, subnet=subnet)
                except ValueError as e:
                    print(f"Error: {e}")
                    sys.exit(1)
            else:
                # We'll load IPs from the scan file in run_port_scan()
                ip_list = []
            
            # Use default values for interactive mode
            args = argparse.Namespace(
                output=None,
                format="json",
                no_color=False,
                test_name=test_name,
                port_range=port_range,
                protocols=protocols,
                timeout=timeout,
                scan_file=scan_file,
                verbose=verbose
            )
            max_workers = threads
        else:
            # Minecraft Scanner mode
            # For now, we'll skip this mode since get_minecraft_scan_input() is missing
            print("Error: Minecraft Scanner mode is currently unavailable.")
            sys.exit(1)
            
            # Exit if no valid input
            if not start_ip and not end_ip and not subnet:
                print("Error: No valid IP range or subnet provided. Exiting.")
                sys.exit(1)
            
            # Get IP list from user input
            try:
                ip_list = parse_ip_input(start_ip=start_ip, end_ip=end_ip, subnet=subnet)
            except ValueError as e:
                print(f"Error: {e}")
                sys.exit(1)
            
            # Use default values for interactive mode
            args = argparse.Namespace(
                output=None,
                format="json",
                no_color=False,
                test_name=test_name,
                port_range=port_range,
                timeout=timeout,
                skip_socket_check=skip_socket_check,
                retries=retries,
                batch_size=batch_size,
                delay_between_batches=delay,
                verbose=verbose
            )
            max_workers = threads
    
    # Check if IP list is empty
    if not ip_list:
        print("Error: No IP addresses to scan. Exiting.")
        sys.exit(1)
    
    # Run the appropriate scan based on mode
    if scan_mode == 'ip':
        print(f"Preparing to scan {len(ip_list)} IP addresses...")
        
        # Run the IP scan
        verbose = args.verbose if hasattr(args, 'verbose') else False
        results = run_scan(ip_list, args.method if hasattr(args, 'method') else "ping", max_workers, verbose)
        
        # Display results
        active_ips = results['active_ips']['ips']
        inactive_ips = results['inactive_ips']['ips']
        formatted_results = format_scan_results(active_ips, inactive_ips, results)
        print("\n" + formatted_results)
    elif scan_mode == 'port':
        # Run the Port scan
        port_range = args.port_range if hasattr(args, 'port_range') else (1, 1024)
        protocols = args.protocols if hasattr(args, 'protocols') else ['tcp', 'udp']
        timeout = args.timeout if hasattr(args, 'timeout') else 1.0
        scan_file = args.scan_file if hasattr(args, 'scan_file') else None
        
        if scan_file:
            print(f"Preparing to scan ports on active IPs from {scan_file}...")
            results = run_port_scan(
                scan_file=scan_file,
                port_range=port_range,
                protocols=protocols,
                timeout=timeout,
                max_workers=max_workers
            )
        else:
            print(f"Preparing to scan ports on {len(ip_list)} IP addresses...")
            results = run_port_scan(
                ip_list=ip_list,
                port_range=port_range,
                protocols=protocols,
                timeout=timeout,
                max_workers=max_workers
            )
        
        # Display a summary of the results
        total_open_tcp = results['open_ports']['tcp_count']
        total_open_udp = results['open_ports']['udp_count']
        total_open = results['open_ports']['count']
        
        print(f"\nPort scan completed.")
        print(f"Found a total of {total_open} open ports ({total_open_tcp} TCP, {total_open_udp} UDP) across {results['total_ips']} IP addresses.")
        print(f"Port range scanned: {port_range[0]}-{port_range[1]}")
        print(f"Protocols scanned: {', '.join(protocols)}")
    else:
        # Run the Minecraft scan (beautified display is handled within the scan function)
        port_range = args.port_range if hasattr(args, 'port_range') else (2048, 30000)
        timeout = args.timeout if hasattr(args, 'timeout') else 2.0
        skip_socket_check = args.skip_socket_check if hasattr(args, 'skip_socket_check') else False
        retries = args.retries if hasattr(args, 'retries') else 2
        batch_size = args.batch_size if hasattr(args, 'batch_size') else 100
        delay_between_batches = args.delay_between_batches if hasattr(args, 'delay_between_batches') else 1.0
        verbose = args.verbose if hasattr(args, 'verbose') else False
        
        results = run_minecraft_scan(
            ip_list, 
            max_workers,
            port_range,
            timeout,
            skip_socket_check,
            retries,
            batch_size,
            delay_between_batches,
            verbose
        )
        
        # Display a formatted summary of the results
        minecraft_servers = results['minecraft_servers']['servers']
        formatted_results = format_minecraft_results(minecraft_servers)
        print("\n" + formatted_results)
    
    # Save results if requested
    if hasattr(args, 'output') and args.output:
        output_file = args.output
        format_type = args.format
    else:
        output_file = None
        format_type = 'json' if hasattr(args, 'format') else 'json'
    
    # Pass test_name if available
    test_name = args.test_name if hasattr(args, 'test_name') else None
    saved_file = save_results_to_file(results, output_file, format_type, test_name)
    print(f"Results saved to: {saved_file}")
    
    # If this was a port scan, also save a simplified version with just the open ports
    if scan_mode == 'port':
        # Create a simplified version of the results with just the open ports
        simplified_results = {}
        for ip, ports in results['open_ports']['by_ip'].items():
            tcp_ports = sorted(ports['tcp'])
            udp_ports = sorted(ports['udp'])
            if tcp_ports or udp_ports:
                simplified_results[ip] = {
                    'tcp': tcp_ports,
                    'udp': udp_ports
                }
        
        # Save the simplified results
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        simplified_file = f"open_ports_{timestamp}.{format_type}"
        simplified_test_name = f"{test_name} - Open Ports Only" if test_name else "Open Ports Only"
        saved_simplified_file = save_results_to_file({'open_ports': simplified_results}, simplified_file, format_type, simplified_test_name)
        print(f"Open ports saved to: {saved_simplified_file}")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\nScan interrupted by user. Exiting.")
        sys.exit(0)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
