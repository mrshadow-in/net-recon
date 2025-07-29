#!/usr/bin/env python3
"""
ROCON IP Scanner Tool

A CLI tool for scanning IP ranges or subnets to identify active and inactive IP addresses.
"""
import argparse
import sys
import time
from typing import Dict, List, Tuple, Optional, Any

from ip_utils import validate_ip, validate_subnet, parse_ip_input
from network_scanner import scan_with_progress, get_active_inactive_ips, scan_minecraft_servers_with_progress
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
    
    return parser.parse_args()


def get_scan_mode() -> str:
    """
    Get the scan mode from the user.
    
    Returns:
        str: Scan mode ('ip' or 'minecraft')
    """
    print("ROCON Scanner - Select Mode")
    print("===========================")
    print("1. IP Scanner (Ping/Socket)")
    print("2. Minecraft Port Scanner")
    
    while True:
        choice = input("\nEnter your choice (1 or 2): ").strip()
        if choice == '1':
            return 'ip'
        elif choice == '2':
            return 'minecraft'
        else:
            print("Invalid choice. Please enter 1 or 2.")


def get_user_input() -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
    """
    Get IP range or subnet input from the user interactively for IP scanning.
    
    Returns:
        Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]: (start_ip, end_ip, subnet, test_name)
    """
    print("\nROCON IP Scanner - Interactive Mode")
    print("===================================")
    
    # Get test name
    test_name = input("Name of Test: ").strip()
    
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
    
    return start_ip, end_ip, subnet, test_name


def get_minecraft_scan_input() -> Tuple[Optional[str], Optional[str], Optional[str], int, Optional[str]]:
    """
    Get input for Minecraft server scanning.
    
    Returns:
        Tuple[Optional[str], Optional[str], Optional[str], int, Optional[str]]: 
            (start_ip, end_ip, subnet, threads, test_name)
    """
    print("\nROCON Minecraft Scanner - Interactive Mode")
    print("=========================================")
    
    # Get test name
    test_name = input("Name of Test: ").strip()
    
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
    
    # Get number of threads
    threads = 50  # Default value
    threads_input = input(f"Number of threads to use (default: {threads}): ").strip()
    if threads_input:
        try:
            threads = int(threads_input)
            if threads < 1:
                print("Number of threads must be at least 1. Using default value.")
                threads = 50
        except ValueError:
            print("Invalid number of threads. Using default value.")
    
    return start_ip, end_ip, subnet, threads, test_name


def run_scan(ip_list: List[str], method: str = "ping", max_workers: int = 50) -> Dict:
    """
    Run the IP scan and return the results.
    
    Args:
        ip_list: List of IP addresses to scan
        method: Scanning method ('ping' or 'socket')
        max_workers: Maximum number of concurrent workers
        
    Returns:
        Dict: Scan results summary
    """
    start_time = time.time()
    
    # Run the scan with progress reporting
    scan_results = scan_with_progress(ip_list, method, max_workers)
    
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


def run_minecraft_scan(ip_list: List[str], max_workers: int = 50) -> Dict[str, Any]:
    """
    Run the Minecraft server scan and return the results.
    
    Args:
        ip_list: List of IP addresses to scan
        max_workers: Maximum number of concurrent workers
        
    Returns:
        Dict[str, Any]: Minecraft scan results
    """
    start_time = time.time()
    
    # Run the Minecraft scan with progress reporting
    minecraft_results = scan_minecraft_servers_with_progress(ip_list, (2048, 30000), max_workers)
    
    # Create scan info
    scan_duration = time.time() - start_time
    
    # Format results
    results = {
        'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),
        'duration': scan_duration,
        'scan_method': 'minecraft',
        'port_range': [2048, 30000],
        'total_ips': len(ip_list),
        'minecraft_servers': {
            'count': len(minecraft_results),
            'percentage': (len(minecraft_results) / len(ip_list) * 100) if ip_list else 0,
            'servers': minecraft_results
        }
    }
    
    return results


def format_minecraft_results(minecraft_results: Dict[str, List[int]]) -> str:
    """
    Format Minecraft scan results for console display.
    
    Args:
        minecraft_results: Dictionary mapping IP addresses to lists of ports
        
    Returns:
        str: Formatted string representation of the Minecraft scan results
    """
    # Create a horizontal line for separation
    separator = "=" * 80
    
    # Format header
    header = ["ROCON MINECRAFT SCANNER - SCAN RESULTS", separator]
    
    # Format server list
    if minecraft_results:
        server_count = len(minecraft_results)
        server_section = [f"MINECRAFT SERVERS FOUND: {server_count}"]
        
        for ip, ports in minecraft_results.items():
            server_section.append(f"  {ip}: {', '.join(map(str, ports))}")
    else:
        server_section = ["NO MINECRAFT SERVERS FOUND"]
    
    # Combine all sections
    sections = header + [""] + server_section + ["", separator]
    
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
            start_ip, end_ip, subnet, test_name = get_user_input()
            
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
                test_name=test_name
            )
            max_workers = args.workers
        else:
            # Minecraft Scanner mode
            start_ip, end_ip, subnet, threads, test_name = get_minecraft_scan_input()
            
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
                test_name=test_name
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
        results = run_scan(ip_list, args.method if hasattr(args, 'method') else "ping", max_workers)
        
        # Display results
        active_ips = results['active_ips']['ips']
        inactive_ips = results['inactive_ips']['ips']
        formatted_results = format_scan_results(active_ips, inactive_ips, results)
        print("\n" + formatted_results)
    else:
        # Run the Minecraft scan (beautified display is handled within the scan function)
        results = run_minecraft_scan(ip_list, max_workers)
    
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


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\nScan interrupted by user. Exiting.")
        sys.exit(0)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
