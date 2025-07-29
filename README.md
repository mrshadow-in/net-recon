# ROCON IP Scanner

A command-line tool for scanning IP ranges or subnets to identify active and inactive IP addresses.

## Features

- Scan IP ranges (e.g., 192.168.1.1 to 192.168.1.254)
- Scan IP subnets in CIDR notation (e.g., 192.168.1.0/24)
- Parallel scanning for improved performance
- Beautified console output with color-coding
- Save results in multiple formats (JSON, TXT, CSV)
- Interactive mode for easy usage
- Modular design for future extensions

## Installation

### Prerequisites

- Python 3.6 or higher
- No external dependencies required (uses standard library modules)

### Setup

1. Clone the repository or download the source code:

```bash
git clone https://github.com/yourusername/rocon-ip-scanner.git
cd rocon-ip-scanner
```

2. Make the script executable (Linux/macOS):

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

In interactive mode, you'll be prompted to enter:
- Start IP address
- End IP address
- Subnet (if no IP range is provided)

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

## Output Example

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

## Project Structure

- `main.py`: Main entry point and CLI interface
- `ip_utils.py`: IP address validation, parsing, and range generation
- `network_scanner.py`: Network scanning functionality
- `output_formatter.py`: Output formatting and file saving
- `test_scanner.py`: Unit tests for the tool

## Extending the Tool

The tool is designed with a modular approach to make it easy to extend with new features:

1. Add new scanning methods in `network_scanner.py`
2. Add new output formats in `output_formatter.py`
3. Add new command-line options in `main.py`

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Built with Python's standard library
- Developed as part of the ROCON tools suite