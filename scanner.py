#!/usr/bin/env python3
"""
Advanced Network Scanner
Author: Adarsh Pratap Singh
Description: Multi-threaded network scanner with service detection and vulnerability identification
"""

import socket
import threading
import argparse
import sys
import time
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import subprocess
import re

class NetworkScanner:
    def __init__(self, target, threads=100, timeout=1):
        """
        Initialize the network scanner
        
        Args:
            target (str): Target IP address or hostname
            threads (int): Number of threads for scanning
            timeout (int): Socket timeout in seconds
        """
        self.target = target
        self.threads = threads
        self.timeout = timeout
        self.open_ports = []
        self.services = {}
        self.vulnerabilities = []
        
        # Common service banners and their associated services
        self.service_banners = {
            'SSH': ['SSH', 'OpenSSH'],
            'HTTP': ['HTTP', 'Apache', 'nginx', 'IIS'],
            'HTTPS': ['HTTPS', 'SSL', 'TLS'],
            'FTP': ['FTP', 'vsftpd', 'ProFTPD'],
            'SMTP': ['SMTP', 'Postfix', 'Sendmail'],
            'POP3': ['POP3'],
            'IMAP': ['IMAP'],
            'DNS': ['DNS', 'BIND'],
            'MYSQL': ['MySQL'],
            'POSTGRESQL': ['PostgreSQL'],
            'TELNET': ['Telnet'],
            'SNMP': ['SNMP']
        }
        
        # Common vulnerable services and versions
        self.vulnerable_services = {
            'vsftpd 2.3.4': 'Backdoor vulnerability (CVE-2011-2523)',
            'OpenSSH 7.4': 'Username enumeration (CVE-2018-15473)',
            'Apache 2.4.49': 'Path traversal (CVE-2021-41773)',
            'nginx 1.20.0': 'DNS resolver vulnerability (CVE-2021-23017)'
        }

    def resolve_hostname(self, hostname):
        """
        Resolve hostname to IP address
        
        Args:
            hostname (str): Hostname to resolve
            
        Returns:
            str: IP address or None if resolution fails
        """
        try:
            return socket.gethostbyname(hostname)
        except socket.gaierror:
            print(f"[ERROR] Could not resolve hostname: {hostname}")
            return None

    def scan_port(self, port):
        """
        Scan a single port
        
        Args:
            port (int): Port number to scan
            
        Returns:
            bool: True if port is open, False otherwise
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            sock.close()
            
            if result == 0:
                return True
            return False
        except Exception as e:
            return False

    def grab_banner(self, port):
        """
        Attempt to grab service banner from open port
        
        Args:
            port (int): Port number to grab banner from
            
        Returns:
            str: Service banner or None
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, port))
            
            # Send HTTP request for web services
            if port in [80, 8080, 8000]:
                sock.send(b"GET / HTTP/1.1\r\nHost: " + self.target.encode() + b"\r\n\r\n")
            elif port == 443:
                sock.send(b"GET / HTTP/1.1\r\nHost: " + self.target.encode() + b"\r\n\r\n")
            elif port == 21:  # FTP
                pass  # FTP sends banner automatically
            elif port == 22:  # SSH
                pass  # SSH sends banner automatically
            elif port == 25:  # SMTP
                sock.send(b"EHLO test\r\n")
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            return banner
        except Exception as e:
            return None

    def identify_service(self, port, banner):
        """
        Identify service based on port and banner
        
        Args:
            port (int): Port number
            banner (str): Service banner
            
        Returns:
            str: Identified service name
        """
        # Common port mappings
        common_ports = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            993: 'IMAPS',
            995: 'POP3S',
            3306: 'MySQL',
            5432: 'PostgreSQL',
            1433: 'MSSQL',
            3389: 'RDP',
            5900: 'VNC'
        }
        
        service = common_ports.get(port, 'Unknown')
        
        # Refine service identification based on banner
        if banner:
            banner_lower = banner.lower()
            for service_name, keywords in self.service_banners.items():
                for keyword in keywords:
                    if keyword.lower() in banner_lower:
                        service = service_name
                        break
        
        return service

    def check_vulnerabilities(self, service, banner):
        """
        Check for known vulnerabilities based on service and banner
        
        Args:
            service (str): Service name
            banner (str): Service banner
            
        Returns:
            list: List of potential vulnerabilities
        """
        vulnerabilities = []
        
        if banner:
            for vuln_service, description in self.vulnerable_services.items():
                if vuln_service.lower() in banner.lower():
                    vulnerabilities.append({
                        'service': vuln_service,
                        'description': description,
                        'severity': 'High'
                    })
        
        # Check for default credentials
        if service == 'FTP' and banner and 'vsftpd' in banner.lower():
            vulnerabilities.append({
                'service': 'FTP',
                'description': 'Potential anonymous login enabled',
                'severity': 'Medium'
            })
        
        if service == 'SSH' and banner and 'openssh' in banner.lower():
            vulnerabilities.append({
                'service': 'SSH',
                'description': 'Check for weak authentication methods',
                'severity': 'Low'
            })
        
        return vulnerabilities

    def scan_range(self, start_port, end_port):
        """
        Scan a range of ports using threading
        
        Args:
            start_port (int): Starting port number
            end_port (int): Ending port number
        """
        print(f"[INFO] Scanning {self.target} from port {start_port} to {end_port}")
        print(f"[INFO] Using {self.threads} threads with {self.timeout}s timeout")
        print("-" * 60)
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            # Submit all port scan tasks
            future_to_port = {
                executor.submit(self.scan_port, port): port 
                for port in range(start_port, end_port + 1)
            }
            
            # Process completed tasks
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    if future.result():
                        self.open_ports.append(port)
                        print(f"[OPEN] Port {port}")
                        
                        # Grab banner and identify service
                        banner = self.grab_banner(port)
                        service = self.identify_service(port, banner)
                        
                        self.services[port] = {
                            'service': service,
                            'banner': banner or 'No banner'
                        }
                        
                        # Check for vulnerabilities
                        vulns = self.check_vulnerabilities(service, banner)
                        if vulns:
                            self.vulnerabilities.extend([{**v, 'port': port} for v in vulns])
                        
                except Exception as e:
                    print(f"[ERROR] Error scanning port {port}: {e}")

    def generate_report(self, output_file=None):
        """
        Generate a comprehensive scan report
        
        Args:
            output_file (str): Optional output file path
        """
        report = {
            'scan_info': {
                'target': self.target,
                'scan_time': datetime.now().isoformat(),
                'total_ports_scanned': len(range(1, 65536)),
                'open_ports_found': len(self.open_ports)
            },
            'open_ports': self.open_ports,
            'services': self.services,
            'vulnerabilities': self.vulnerabilities
        }
        
        # Print summary to console
        print("\n" + "=" * 60)
        print("SCAN SUMMARY")
        print("=" * 60)
        print(f"Target: {self.target}")
        print(f"Scan completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Open ports found: {len(self.open_ports)}")
        
        if self.open_ports:
            print("\nOPEN PORTS AND SERVICES:")
            print("-" * 40)
            for port in sorted(self.open_ports):
                service_info = self.services.get(port, {})
                service = service_info.get('service', 'Unknown')
                banner = service_info.get('banner', 'No banner')
                print(f"Port {port:5d}: {service:10s} - {banner[:50]}")
        
        if self.vulnerabilities:
            print("\nPOTENTIAL VULNERABILITIES:")
            print("-" * 40)
            for vuln in self.vulnerabilities:
                print(f"Port {vuln['port']:5d}: [{vuln['severity']}] {vuln['description']}")
        
        # Save to file if specified
        if output_file:
            try:
                with open(output_file, 'w') as f:
                    json.dump(report, f, indent=2)
                print(f"\n[INFO] Report saved to {output_file}")
            except Exception as e:
                print(f"[ERROR] Could not save report: {e}")
        
        return report

def main():
    """Main function to handle command line arguments and run the scanner"""
    parser = argparse.ArgumentParser(
        description="Advanced Network Scanner with Service Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scanner.py 192.168.1.1
  python scanner.py example.com -p 1-1000 -t 50
  python scanner.py 10.0.0.1 -p 80,443,22 -o report.json
        """
    )
    
    parser.add_argument('target', help='Target IP address or hostname')
    parser.add_argument('-p', '--ports', default='1-1000', 
                       help='Port range (e.g., 1-1000) or specific ports (e.g., 80,443,22)')
    parser.add_argument('-t', '--threads', type=int, default=100,
                       help='Number of threads (default: 100)')
    parser.add_argument('--timeout', type=int, default=1,
                       help='Socket timeout in seconds (default: 1)')
    parser.add_argument('-o', '--output', help='Output file for JSON report')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose output')
    
    args = parser.parse_args()
    
    # Parse port specification
    if '-' in args.ports:
        start_port, end_port = map(int, args.ports.split('-'))
    elif ',' in args.ports:
        # Handle specific ports (implement if needed)
        print("[ERROR] Specific port lists not implemented yet. Use range format (e.g., 1-1000)")
        sys.exit(1)
    else:
        start_port = end_port = int(args.ports)
    
    # Validate port range
    if start_port < 1 or end_port > 65535 or start_port > end_port:
        print("[ERROR] Invalid port range. Ports must be between 1-65535")
        sys.exit(1)
    
    # Initialize scanner
    scanner = NetworkScanner(args.target, args.threads, args.timeout)
    
    # Resolve hostname if necessary
    if not args.target.replace('.', '').isdigit():
        resolved_ip = scanner.resolve_hostname(args.target)
        if not resolved_ip:
            sys.exit(1)
        scanner.target = resolved_ip
        print(f"[INFO] Resolved {args.target} to {resolved_ip}")
    
    try:
        # Start scanning
        start_time = time.time()
        scanner.scan_range(start_port, end_port)
        end_time = time.time()
        
        print(f"\n[INFO] Scan completed in {end_time - start_time:.2f} seconds")
        
        # Generate report
        scanner.generate_report(args.output)
        
    except KeyboardInterrupt:
        print("\n[INFO] Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"[ERROR] Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()