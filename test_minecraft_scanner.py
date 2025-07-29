#!/usr/bin/env python3
"""
Test script for the Minecraft scanner with beautified progress display.
This script simulates a Minecraft scan with a small number of IPs.
"""
import time
import random
from network_scanner import scan_minecraft_servers_with_progress

def simulate_minecraft_scan():
    """
    Simulate a Minecraft scan with a small number of IPs.
    """
    # Create a small list of test IPs
    test_ips = [
        "192.168.1.100",
        "192.168.1.101",
        "192.168.1.102",
        "192.168.1.103",
        "192.168.1.104"
    ]
    
    # Mock the scan_minecraft_ports function to avoid actual network scanning
    # This is done by monkey patching the function in the module
    import network_scanner
    
    # Store the original function
    original_scan_minecraft_ports = network_scanner.scan_minecraft_ports
    
    # Define a mock function that simulates port scanning
    def mock_scan_minecraft_ports(ip, port_range, max_workers, timeout):
        # Simulate scanning delay
        time.sleep(random.uniform(1.0, 3.0))
        
        # Randomly decide if this IP has Minecraft servers
        if random.random() < 0.4:  # 40% chance of finding servers
            # Return 1-3 random ports
            num_ports = random.randint(1, 3)
            return random.sample(range(port_range[0], port_range[1]), num_ports)
        else:
            return []
    
    try:
        # Replace the original function with our mock
        network_scanner.scan_minecraft_ports = mock_scan_minecraft_ports
        
        # Run the scan with our beautified progress display
        print("\nStarting simulated Minecraft scan with beautified progress display...\n")
        results = scan_minecraft_servers_with_progress(test_ips, (25000, 30000), 20)
        
        # Print the results dictionary for verification
        print("\nResults dictionary:")
        print(results)
        
    finally:
        # Restore the original function
        network_scanner.scan_minecraft_ports = original_scan_minecraft_ports

if __name__ == "__main__":
    simulate_minecraft_scan()