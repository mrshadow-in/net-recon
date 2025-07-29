# ROCON Scanner

A command-line tool for scanning IP ranges or subnets to identify active and inactive IP addresses, as well as Minecraft servers.

## Features

- Scan IP ranges (e.g., 192.168.1.1 to 192.168.1.254)
- Scan IP subnets in CIDR notation (e.g., 192.168.1.0/24)
- Parallel scanning for improved performance
- Beautified console output with color-coding
- Save results in multiple formats (JSON, TXT, CSV)
- Interactive mode for easy usage
- Modular design for future extensions
- Test name input and organized output directories
- Minecraft server port scanner with configurable port range
- Configurable thread count for optimized scanning speed
- Beautified live progress display for Minecraft scanning

## Installation

### Prerequisites

- Python 3.6 or higher
- No runtime dependencies required (uses standard library modules)
- Development dependencies (for contributors):
  - pytest: For running tests
  - pytest-cov: For test coverage reporting
  - flake8: For code linting
  - black: For code formatting

### Setup

1. Clone the repository or download the source code:

```bash
git clone https://github.com/yourusername/rocon-ip-scanner.git
cd rocon-ip-scanner
```

2. (Optional) Install development dependencies:

```bash
pip install -r requirements.txt
```

3. Make the script executable (Linux/macOS):

```bash
chmod +x main.py
```

## Usage

### Command-line Arguments

```
usage: main.py [-h] (--range START_IP END_IP | --subnet SUBNET)
               [--method {ping,socket}] [--workers WORKERS]
               [--output FILE] [--format {json,txt,csv}] [--no-color]

ROCON IP Scanner - Scan IP ranges or subnets for active hosts

options:
  -h, --help            show this help message and exit

required arguments (one of):
  --range START_IP END_IP, -r START_IP END_IP
                        Specify an IP range to scan (e.g., 192.168.1.1 192.168.1.254)
  --subnet SUBNET, -s SUBNET
                        Specify a subnet to scan in CIDR notation (e.g., 192.168.1.0/24)

Scan Options:
  --method {ping,socket}, -m {ping,socket}
                        Method to use for scanning (ping or socket) (default: ping)
  --workers WORKERS, -w WORKERS
                        Maximum number of concurrent workers for scanning (default: 50)

Output Options:
  --output FILE, -o FILE
                        Save results to a file (default: scan_results_TIMESTAMP.json)
  --format {json,txt,csv}, -f {json,txt,csv}
                        Format for saving results (default: json)
  --no-color            Disable colored output in the console (default: False)
```

### Interactive Mode

If you run the script without any arguments, it will enter interactive mode:

```bash
python main.py
```

In interactive mode, you'll first be prompted to select a scan mode:
1. IP Scanner (Ping/Socket)
2. Minecraft Port Scanner

Then, you'll be prompted to enter:
- Name of Test (creates organized output directories)
- Start IP address
- End IP address
- Subnet (if no IP range is provided)

For Minecraft scanning, you'll also be prompted to enter:
- Port range to scan (start port and end port)
- Number of threads to use for scanning

### Examples

#### Scan an IP Range

```bash
python main.py --range 192.168.1.1 192.168.1.10
```

#### Scan a Subnet

```bash
python main.py --subnet 192.168.1.0/24
```

#### Use Socket Method Instead of Ping

```bash
python main.py --subnet 192.168.1.0/24 --method socket
```

#### Save Results to a Specific File in CSV Format

```bash
python main.py --subnet 192.168.1.0/24 --output results.csv --format csv
```

#### Increase Number of Workers for Faster Scanning

```bash
python main.py --subnet 192.168.1.0/24 --workers 100
```

## Minecraft Port Scanner

The Minecraft Port Scanner allows you to scan IP ranges or subnets for Minecraft servers on user-defined port ranges. This feature is currently available only in interactive mode.

### How It Works

1. The scanner checks each IP in the specified range or subnet
2. For each IP, it scans the user-defined port range (default: 2048-30000) using multi-threading
3. It detects Minecraft servers using two methods:
   - First, it attempts a quick socket connection to check if the port is open
   - Then, it uses the mcsrvstat.us API to reliably identify Minecraft servers and gather detailed information
4. Results are saved in the specified test directory structure

### API Integration

The scanner uses the [mcsrvstat.us API](https://api.mcsrvstat.us/) to reliably detect Minecraft servers and gather detailed information:

- **Server Version**: Identifies the Minecraft version running on the server
- **Player Information**: Shows online/max players and lists currently connected players
- **MOTD (Message of the Day)**: Displays the server's welcome message
- **Server Software**: Identifies the server software (e.g., Vanilla, Spigot, Paper)
- **Additional Details**: Provides hostname, protocol version, and other server-specific information

This API integration ensures reliable detection and provides much more detailed information than traditional port scanning methods. The API is cached for 5 minutes and requires a proper User-Agent header, which is automatically handled by the scanner.

### Configurable Port Range

You can specify your own port range to scan:
- Default range is 2048-30000 if no custom range is provided
- Enter custom start port and end port during the interactive setup
- The scanner validates that ports are within valid range (1-65535)
- If start port is greater than end port, they will be automatically swapped

### Beautified Live Progress Display

The Minecraft scanner features a beautified live progress display that provides real-time feedback during scanning:

- **Dual Progress Bars**: Shows both IP scanning progress and port scanning progress simultaneously
  - IP Progress Bar: Tracks overall completion of IP addresses being scanned
  - Port Progress Bar: Shows real-time progress of ports being scanned on the current IP
- **Live Port Tracking**: Displays the current port being scanned in real-time
- **Color-Coded Status**: Different colors indicate different status messages (green for success, red for no servers found)
- **Real-Time Statistics**: Displays elapsed time, estimated time remaining, and scan rate
- **In-Place Updates**: The display updates in-place rather than printing new lines, creating a cleaner interface
- **Summary Report**: Provides a detailed summary of results when the scan completes

This enhanced display makes it easier to monitor long-running scans at both the IP and port levels, providing a more comprehensive and professional user experience. The dual progress bars allow you to track both the overall scan progress and the detailed progress of the current IP being scanned.

### Performance Optimization

- You can specify the number of threads to use for scanning
- Higher thread counts can significantly improve scanning speed, especially for large port ranges
- The scanner is optimized to minimize false positives and negatives

### Advanced Reliability Options

The Minecraft scanner includes several advanced options to improve reliability, especially for challenging networks or specific IP ranges:

- **Skip Socket Check**: Bypasses the initial socket connection check and directly uses the API for all ports
  - More reliable for detecting servers behind firewalls or with unusual configurations
  - Slower but more thorough, as it checks all ports with the API
  - Recommended for problematic IPs where standard detection fails

- **Timeout Configuration**: Adjust the timeout for socket connections and API calls
  - Default is 2.0 seconds, which works well for most networks
  - Increase for slow or congested networks
  - Decrease for faster scanning on reliable networks

- **Retry Mechanism**: Automatically retry failed API calls
  - Default is 2 retries with exponential backoff
  - Helps overcome temporary network issues or API rate limiting
  - Particularly useful for large scans or when the API is under heavy load

- **Batch Processing**: Process ports in smaller batches to avoid overwhelming the API
  - Default batch size is 100 ports
  - Smaller batches are more reliable but slower
  - Larger batches are faster but may trigger rate limiting

- **Delay Between Batches**: Add a delay between processing batches of ports
  - Default is 1.0 second between batches
  - Helps avoid API rate limiting for large scans
  - Adjust based on scan size and network conditions

- **Verbose Mode**: Enable detailed logging for troubleshooting
  - Shows detailed information about each step of the scanning process
  - Helps diagnose issues with specific IPs or ports
  - Useful for understanding why servers aren't being detected

These options are available in the interactive mode and can be configured based on your specific needs. For particularly challenging scans (like the IP range 129.154.37.211 with ports 25565-25599), using a combination of these options can significantly improve detection rates.

## Output Examples

### IP Scanner Output

```
ROCON IP SCANNER - SCAN RESULTS
================================================================================
Timestamp: 2025-07-29 23:59:44
Duration: 0.09 seconds
Scan Type: IP Scan
================================================================================

ACTIVE IPs (2):
127.0.0.1             127.0.0.2

No inactive IPs found.

================================================================================
Results saved to: scan_results_20250729_235944.json
```

### Minecraft Scanner Output

```
ROCON MINECRAFT SCANNER - SCAN RESULTS
================================================================================

MINECRAFT SERVERS FOUND: 2 IPs with 3 server ports

  IP: 192.168.1.100
    Port: 25565
      Version: 1.19.2
      MOTD: Welcome to our Minecraft server!
      Players: 12/50 online (Steve, Alex, and 10 more)
      Software: Paper

    Port: 25566
      Version: 1.18.2
      MOTD: Creative mode server
      Players: 5/20 online (Builder123, Redstone_Master, Architect99)
      Software: Spigot

  IP: 192.168.1.120
    Port: 25565
      Version: 1.20.1
      MOTD: Survival server - No griefing!
      Players: 8/30 online (Player1, Player2, Player3, and 5 more)
      Software: Vanilla

================================================================================
Note: Server information provided by mcsrvstat.us API
Results saved to: output/minecraft_test/scan_results_20250730_001523.json
```

### Directory Structure

When you provide a test name, the scanner creates the following directory structure:

```
output/
└── test_name/
    ├── activeips/
    │   └── active_ips_TIMESTAMP.json
    ├── inactiveips/
    │   └── inactive_ips_TIMESTAMP.json
    └── scan_results_TIMESTAMP.json
```

## Project Structure

- `main.py`: Main entry point and CLI interface, scan mode selection
- `ip_utils.py`: IP address validation, parsing, and range generation
- `network_scanner.py`: Network scanning functionality, including Minecraft server detection
- `output_formatter.py`: Output formatting, file saving, and test directory creation
- `test_scanner.py`: Unit tests for the tool

## Extending the Tool

The tool is designed with a modular approach to make it easy to extend with new features:

1. Add new scanning methods in `network_scanner.py`
2. Add new output formats in `output_formatter.py`
3. Add new scan modes in `main.py`
4. Add new server type detection in `network_scanner.py`

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Built with Python's standard library
- Minecraft server detection powered by the [mcsrvstat.us API](https://api.mcsrvstat.us/)
- Developed as part of the ROCON tools suite