#!/usr/bin/env python3
"""
Test script to directly check the mcsrvstat.us API with the specific IP and port range.
This will help diagnose why the scanner is not detecting Minecraft servers on this IP.
"""
import urllib.request
import urllib.error
import json
import time
import sys

def check_minecraft_server_api(ip: str, port: int, timeout: float = 10.0, verbose: bool = True):
    """
    Check if a specific IP and port is a Minecraft server using the mcsrvstat.us API.
    
    Args:
        ip: IP address to check
        port: Port to check
        timeout: Timeout in seconds for the API request
        verbose: Whether to print detailed information
        
    Returns:
        dict: Server information if a Minecraft server is detected, None otherwise
    """
    # Construct the API URL
    url = f"https://api.mcsrvstat.us/3/{ip}:{port}"
    
    # Set up the request with a proper User-Agent
    headers = {
        "User-Agent": "ROCON-Scanner-Test/1.0 (https://github.com/yourusername/rocon-ip-scanner)"
    }
    
    if verbose:
        print(f"Testing {ip}:{port} with API...")
    
    try:
        # Create a request object with headers
        req = urllib.request.Request(url, headers=headers)
        
        # Open the URL with timeout
        start_time = time.time()
        with urllib.request.urlopen(req, timeout=timeout) as response:
            # Parse the JSON response
            data = json.loads(response.read().decode('utf-8'))
            elapsed = time.time() - start_time
            
            if verbose:
                print(f"API response received in {elapsed:.2f}s")
                if data.get("online", False):
                    print(f"✅ MINECRAFT SERVER FOUND at {ip}:{port}")
                    print(f"   Version: {data.get('version', 'Unknown')}")
                    players = data.get('players', {})
                    if isinstance(players, dict):
                        print(f"   Players: {players.get('online', '?')}/{players.get('max', '?')}")
                    print(f"   Software: {data.get('software', 'Unknown')}")
                else:
                    print(f"❌ No Minecraft server at {ip}:{port}")
            
            return data
    except urllib.error.HTTPError as e:
        if verbose:
            print(f"❌ HTTP Error: {e.code} {e.reason}")
        return None
    except urllib.error.URLError as e:
        if verbose:
            print(f"❌ URL Error: {e.reason}")
        return None
    except json.JSONDecodeError:
        if verbose:
            print(f"❌ Invalid JSON response from API")
        return None
    except Exception as e:
        if verbose:
            print(f"❌ Error: {str(e)}")
        return None

def main():
    """
    Test the mcsrvstat.us API with the specific IP and port range.
    """
    # The IP address from the issue
    ip = "129.154.37.211"
    
    # Define the port range to test
    start_port = 25565
    end_port = 25599
    
    # Check if command line arguments were provided
    if len(sys.argv) > 1:
        # If a single port is specified, test only that port
        try:
            port = int(sys.argv[1])
            result = check_minecraft_server_api(ip, port)
            sys.exit(0 if result and result.get("online", False) else 1)
        except ValueError:
            print(f"Invalid port: {sys.argv[1]}")
            sys.exit(1)
    
    # Test a few specific ports first
    test_ports = [25565, 25566, 25567, 25570, 25575, 25580, 25585, 25590, 25595, 25599]
    
    print(f"Testing specific ports on {ip}...")
    found_servers = 0
    
    for port in test_ports:
        result = check_minecraft_server_api(ip, port)
        if result and result.get("online", False):
            found_servers += 1
        # Add a delay to avoid rate limiting
        time.sleep(1)
    
    print(f"\nFound {found_servers} Minecraft servers out of {len(test_ports)} tested ports.")
    
    # Ask if user wants to test the full range
    if input("\nTest the full port range 25565-25599? (y/n): ").lower() == 'y':
        print(f"\nTesting all ports in range {start_port}-{end_port} on {ip}...")
        print("This may take some time and could be subject to API rate limiting.")
        
        found_servers = 0
        total_ports = end_port - start_port + 1
        
        for port in range(start_port, end_port + 1):
            result = check_minecraft_server_api(ip, port, verbose=False)
            if result and result.get("online", False):
                found_servers += 1
                print(f"✅ MINECRAFT SERVER FOUND at {ip}:{port}")
            
            # Show progress
            progress = (port - start_port + 1) / total_ports * 100
            print(f"Progress: {progress:.1f}% ({port - start_port + 1}/{total_ports}) - Found: {found_servers}", end='\r')
            
            # Add a delay to avoid rate limiting
            time.sleep(1)
        
        print(f"\n\nFound {found_servers} Minecraft servers out of {total_ports} ports tested.")

if __name__ == "__main__":
    main()