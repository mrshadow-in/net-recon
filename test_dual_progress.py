#!/usr/bin/env python3
"""
Test script for the enhanced Minecraft scanner with dual progress bars.
This script simulates a Minecraft scan with a small number of IPs and ports.
"""
import time
import random
from network_scanner import scan_minecraft_servers_with_progress

def simulate_minecraft_scan():
    """
    Simulate a Minecraft scan with a small number of IPs and a reduced port range.
    """
    # Create a small list of test IPs
    test_ips = [
        "192.168.1.100",
        "192.168.1.101",
        "192.168.1.102",
        "192.168.1.103",
        "192.168.1.104"
    ]
    
    # Use a smaller port range for testing
    port_range = (25000, 25100)  # Just 100 ports instead of thousands
    
    # Mock the check_minecraft_server function to avoid actual network scanning
    # This is done by monkey patching the function in the module
    import network_scanner
    
    # Store the original function
    original_check_minecraft_server = network_scanner.check_minecraft_server
    
    # Define a mock function that simulates port checking with delays
    def mock_check_minecraft_server(ip, port, timeout):
        # Simulate checking delay (smaller for testing)
        time.sleep(random.uniform(0.01, 0.05))
        
        # Randomly decide if this port has a Minecraft server
        # Very low probability to simulate real-world scenario
        return random.random() < 0.02  # 2% chance of finding a server
    
    try:
        # Replace the original function with our mock
        network_scanner.check_minecraft_server = mock_check_minecraft_server
        
        # Run the scan with our dual progress display
        print("\nStarting simulated Minecraft scan with dual progress bars...\n")
        results = scan_minecraft_servers_with_progress(test_ips, port_range, 20, 0.1)
        
        # Print the results dictionary for verification
        print("\nResults dictionary:")
        print(results)
        
    finally:
        # Restore the original function
        network_scanner.check_minecraft_server = original_check_minecraft_server

if __name__ == "__main__":
    simulate_minecraft_scan()