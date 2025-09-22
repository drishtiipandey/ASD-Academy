"""
This module provides the NetworkScanner class for scanning networks and hosts.
It uses nmap to detect live hosts and open ports.
Used for network reconnaissance in CyberSuite.
"""
import os
os.environ["PATH"] += os.pathsep + r"C:\Program Files (x86)\Nmap"
import nmap  # Import the nmap library for network scanning
import socket  # For local IP detection if needed

class NetworkScanner:
    def __init__(self):
        # Initialize the nmap PortScanner object
        self.scanner = nmap.PortScanner()

    def quick_scan(self, target_ip: str) -> dict:
        """
        Perform a quick scan on the target IP address.
        Returns a dictionary mapping each live host to its list of open ports.
        """
        results = {}  # Dictionary to store scan results
        
        # First, perform a ping scan to find live hosts
        self.scanner.scan(hosts=target_ip, arguments="-sn")
        
        # Iterate through all detected hosts
        for host in self.scanner.all_hosts():
            # Check if the host is up (responding to ping)
            if self.scanner[host].state() == "up":
                # For each live host, check its open ports
                results[host] = self._check_ports(host)
        
        return results

    def _check_ports(self, host: str) -> list:
        """
        Helper function to check common ports on a single host.
        Returns a list of open ports in the format 'port/protocol'.
        """
        # Perform a fast scan on the host to check common ports
        self.scanner.scan(hosts=host, arguments="-F")  # Fast scan
        open_ports = []  # List to store open ports
        
        # Iterate through all protocols detected on the host
        for proto in self.scanner[host].all_protocols():
            # For each protocol, check all ports
            for port, info in self.scanner[host][proto].items():
                # If the port is open, add it to the list
                if info['state'] == "open":
                    open_ports.append(f"{port}/{proto}")
        
        return open_ports