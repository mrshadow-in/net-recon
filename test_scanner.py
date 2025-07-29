"""
Test script for the ROCON IP Scanner tool.
This script tests various functionalities of the IP scanner.
"""
import sys
import os
import unittest
from unittest.mock import patch, MagicMock
import ipaddress

# Import modules from the project
from ip_utils import validate_ip, validate_subnet, parse_ip_input, get_ip_range, get_ips_from_subnet
from network_scanner import ping_ip, socket_check, scan_ips, get_active_inactive_ips
from output_formatter import format_ip_list, format_scan_results, get_results_summary


class TestIPUtils(unittest.TestCase):
    """Test cases for the IP utilities module."""
    
    def test_validate_ip(self):
        """Test IP validation function."""
        # Valid IPs
        self.assertTrue(validate_ip("192.168.1.1"))
        self.assertTrue(validate_ip("10.0.0.1"))
        self.assertTrue(validate_ip("172.16.0.1"))
        self.assertTrue(validate_ip("8.8.8.8"))
        
        # Invalid IPs
        self.assertFalse(validate_ip("256.168.1.1"))  # Out of range
        self.assertFalse(validate_ip("192.168.1"))    # Incomplete
        self.assertFalse(validate_ip("192.168.1.1.1"))  # Too many octets
        self.assertFalse(validate_ip("test"))         # Not an IP
    
    def test_validate_subnet(self):
        """Test subnet validation function."""
        # Valid subnets
        self.assertTrue(validate_subnet("192.168.1.0/24"))
        self.assertTrue(validate_subnet("10.0.0.0/8"))
        self.assertTrue(validate_subnet("172.16.0.0/16"))
        
        # Invalid subnets
        self.assertFalse(validate_subnet("256.168.1.0/24"))  # Invalid IP
        self.assertFalse(validate_subnet("192.168.1.0/33"))  # Invalid prefix
        self.assertFalse(validate_subnet("192.168.1.0"))     # Missing prefix
        self.assertFalse(validate_subnet("test"))            # Not a subnet
    
    def test_get_ip_range(self):
        """Test IP range generation."""
        # Test small range
        ip_range = get_ip_range("192.168.1.1", "192.168.1.5")
        expected = ["192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4", "192.168.1.5"]
        self.assertEqual(ip_range, expected)
        
        # Test range with start > end (should swap)
        ip_range = get_ip_range("192.168.1.5", "192.168.1.1")
        self.assertEqual(ip_range, expected)
        
        # Test invalid IPs
        with self.assertRaises(ValueError):
            get_ip_range("invalid", "192.168.1.5")
        with self.assertRaises(ValueError):
            get_ip_range("192.168.1.1", "invalid")
    
    def test_get_ips_from_subnet(self):
        """Test IP extraction from subnet."""
        # Test small subnet
        ips = get_ips_from_subnet("192.168.1.0/30")
        expected = ["192.168.1.1", "192.168.1.2"]  # Excluding network and broadcast
        self.assertEqual(ips, expected)
        
        # Test /31 subnet (no network/broadcast addresses)
        ips = get_ips_from_subnet("192.168.1.0/31")
        expected = ["192.168.1.0", "192.168.1.1"]
        self.assertEqual(ips, expected)
        
        # Test invalid subnet
        with self.assertRaises(ValueError):
            get_ips_from_subnet("invalid")
    
    def test_parse_ip_input(self):
        """Test IP input parsing."""
        # Test with IP range
        ips = parse_ip_input(start_ip="192.168.1.1", end_ip="192.168.1.3")
        expected = ["192.168.1.1", "192.168.1.2", "192.168.1.3"]
        self.assertEqual(ips, expected)
        
        # Test with subnet
        ips = parse_ip_input(subnet="192.168.1.0/30")
        expected = ["192.168.1.1", "192.168.1.2"]
        self.assertEqual(ips, expected)
        
        # Test with insufficient input
        with self.assertRaises(ValueError):
            parse_ip_input()
        with self.assertRaises(ValueError):
            parse_ip_input(start_ip="192.168.1.1")  # Missing end_ip


class TestNetworkScanner(unittest.TestCase):
    """Test cases for the network scanner module."""
    
    @patch('subprocess.call')
    def test_ping_ip(self, mock_call):
        """Test ping function."""
        # Mock successful ping
        mock_call.return_value = 0
        self.assertTrue(ping_ip("8.8.8.8"))
        
        # Mock failed ping
        mock_call.return_value = 1
        self.assertFalse(ping_ip("8.8.8.8"))
        
        # Mock exception
        mock_call.side_effect = Exception("Test exception")
        self.assertFalse(ping_ip("8.8.8.8"))
    
    @patch('socket.socket')
    def test_socket_check(self, mock_socket):
        """Test socket connection function."""
        # Mock successful connection
        mock_socket_instance = MagicMock()
        mock_socket_instance.connect_ex.return_value = 0
        mock_socket.return_value = mock_socket_instance
        self.assertTrue(socket_check("8.8.8.8"))
        
        # Mock failed connection
        mock_socket_instance.connect_ex.return_value = 1
        self.assertFalse(socket_check("8.8.8.8"))
        
        # Mock exception
        mock_socket_instance.connect_ex.side_effect = Exception("Test exception")
        self.assertFalse(socket_check("8.8.8.8"))
    
    @patch('network_scanner.ping_ip')
    def test_scan_ips(self, mock_ping):
        """Test IP scanning function."""
        # Mock ping results
        def mock_ping_side_effect(ip):
            return ip in ["192.168.1.1", "192.168.1.3"]
        
        mock_ping.side_effect = mock_ping_side_effect
        
        # Test scanning
        ip_list = ["192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4"]
        results = scan_ips(ip_list, method="ping", max_workers=2)
        
        expected = {
            "192.168.1.1": True,
            "192.168.1.2": False,
            "192.168.1.3": True,
            "192.168.1.4": False
        }
        self.assertEqual(results, expected)
    
    def test_get_active_inactive_ips(self):
        """Test separation of active and inactive IPs."""
        scan_results = {
            "192.168.1.1": True,
            "192.168.1.2": False,
            "192.168.1.3": True,
            "192.168.1.4": False
        }
        
        active, inactive = get_active_inactive_ips(scan_results)
        
        self.assertEqual(active, ["192.168.1.1", "192.168.1.3"])
        self.assertEqual(inactive, ["192.168.1.2", "192.168.1.4"])


class TestOutputFormatter(unittest.TestCase):
    """Test cases for the output formatter module."""
    
    def test_format_ip_list(self):
        """Test IP list formatting."""
        # Test active IPs formatting
        ip_list = ["192.168.1.1", "192.168.1.3"]
        result = format_ip_list(ip_list, "active", colored=False)
        self.assertIn("ACTIVE IPs (2):", result)
        self.assertIn("192.168.1.1", result)
        self.assertIn("192.168.1.3", result)
        
        # Test empty list
        result = format_ip_list([], "active", colored=False)
        self.assertEqual(result, "No active IPs found.")
    
    def test_format_scan_results(self):
        """Test scan results formatting."""
        active_ips = ["192.168.1.1", "192.168.1.3"]
        inactive_ips = ["192.168.1.2", "192.168.1.4"]
        
        scan_info = {
            "timestamp": "2025-07-29 23:55:00",
            "duration": 1.5,
            "scan_type": "IP Range Scan"
        }
        
        result = format_scan_results(active_ips, inactive_ips, scan_info)
        
        self.assertIn("ROCON IP SCANNER - SCAN RESULTS", result)
        self.assertIn("Timestamp: 2025-07-29 23:55:00", result)
        self.assertIn("Duration: 1.50 seconds", result)
        self.assertIn("Scan Type: IP Range Scan", result)
        self.assertIn("ACTIVE IPs (2):", result)
        self.assertIn("INACTIVE IPs (2):", result)
    
    def test_get_results_summary(self):
        """Test results summary generation."""
        active_ips = ["192.168.1.1", "192.168.1.3"]
        inactive_ips = ["192.168.1.2", "192.168.1.4"]
        
        scan_info = {
            "scan_type": "IP Range Scan",
            "duration": 1.5
        }
        
        summary = get_results_summary(active_ips, inactive_ips, scan_info)
        
        self.assertEqual(summary["total_ips_scanned"], 4)
        self.assertEqual(summary["active_ips"]["count"], 2)
        self.assertEqual(summary["active_ips"]["percentage"], 50.0)
        self.assertEqual(summary["inactive_ips"]["count"], 2)
        self.assertEqual(summary["inactive_ips"]["percentage"], 50.0)
        self.assertEqual(summary["scan_type"], "IP Range Scan")
        self.assertEqual(summary["duration"], 1.5)


def run_tests():
    """Run all test cases."""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    suite.addTests(loader.loadTestsFromTestCase(TestIPUtils))
    suite.addTests(loader.loadTestsFromTestCase(TestNetworkScanner))
    suite.addTests(loader.loadTestsFromTestCase(TestOutputFormatter))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result.wasSuccessful()


if __name__ == "__main__":
    print("Running tests for ROCON IP Scanner...")
    success = run_tests()
    
    if success:
        print("\nAll tests passed successfully!")
        
        # Test the actual CLI with a small subnet
        print("\nRunning a sample scan with a small subnet...")
        os.system(f"{sys.executable} main.py --subnet 127.0.0.1/30 --method ping")
    else:
        print("\nSome tests failed. Please check the output above for details.")
        sys.exit(1)