# Advanced Network Scanner

A comprehensive, multi-threaded network scanner with service detection and vulnerability identification capabilities. This tool demonstrates advanced Python programming skills and cybersecurity knowledge.

## 🚀 Features

- **Multi-threaded Scanning**: Fast port scanning using configurable thread pools
- **Service Detection**: Automatic identification of running services
- **Banner Grabbing**: Retrieves service banners for detailed analysis
- **Vulnerability Assessment**: Identifies potential security issues
- **Comprehensive Reporting**: JSON and console output formats
- **Hostname Resolution**: Supports both IP addresses and hostnames
- **Configurable Parameters**: Customizable threads, timeouts, and port ranges

## 🛠️ Technical Skills Demonstrated

- **Network Programming**: Socket programming, TCP connections
- **Concurrent Programming**: Threading, ThreadPoolExecutor
- **Error Handling**: Robust exception handling and timeout management
- **Data Processing**: JSON serialization, banner analysis
- **Security Knowledge**: Vulnerability identification, service fingerprinting
- **Code Organization**: Clean, modular, well-documented code

## 📋 Requirements

```bash
Python 3.6+
No external dependencies required (uses only standard library)
```

## 🔧 Installation

1. Clone or download the scanner:
```bash
git clone <repository-url>
cd advanced-network-scanner
```

2. Make the script executable (Linux/Mac):
```bash
chmod +x scanner.py
```

## 💻 Usage

### Basic Usage
```bash
# Scan common ports on a target
python scanner.py 192.168.1.1

# Scan specific port range
python scanner.py example.com -p 1-1000

# Use custom thread count and timeout
python scanner.py 10.0.0.1 -p 1-5000 -t 200 --timeout 2

# Save results to JSON file
python scanner.py target.com -o scan_results.json
```

### Command Line Options
```
positional arguments:
  target                Target IP address or hostname

optional arguments:
  -h, --help            Show help message
  -p, --ports PORTS     Port range (e.g., 1-1000) or specific ports
  -t, --threads THREADS Number of threads (default: 100)
  --timeout TIMEOUT     Socket timeout in seconds (default: 1)
  -o, --output OUTPUT   Output file for JSON report
  -v, --verbose         Enable verbose output
```

## 📊 Sample Output

```
[INFO] Scanning 192.168.1.1 from port 1 to 1000
[INFO] Using 100 threads with 1s timeout
------------------------------------------------------------
[OPEN] Port 22
[OPEN] Port 80
[OPEN] Port 443

============================================================
SCAN SUMMARY
============================================================
Target: 192.168.1.1
Scan completed: 2024-01-15 14:30:25
Open ports found: 3

OPEN PORTS AND SERVICES:
----------------------------------------
Port    22: SSH        - SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5
Port    80: HTTP       - HTTP/1.1 200 OK Server: nginx/1.18.0
Port   443: HTTPS      - HTTP/1.1 200 OK Server: nginx/1.18.0

POTENTIAL VULNERABILITIES:
----------------------------------------
Port    22: [Low] Check for weak authentication methods
```

## 🔍 Features Breakdown

### Service Detection
- Automatic service identification based on port numbers
- Banner grabbing for detailed service information
- Support for common protocols (HTTP, SSH, FTP, SMTP, etc.)

### Vulnerability Assessment
- Database of known vulnerable service versions
- Common security misconfigurations detection
- Severity classification (High, Medium, Low)

### Performance Optimization
- Multi-threaded scanning for speed
- Configurable thread pools and timeouts
- Efficient socket handling and resource management

### Reporting
- Real-time console output
- Comprehensive JSON reports
- Structured data for further analysis

## 🔒 Security Considerations

- **Ethical Use**: Only scan systems you own or have permission to test
- **Rate Limiting**: Adjust thread count to avoid overwhelming targets
- **Legal Compliance**: Ensure compliance with local laws and regulations
- **Responsible Disclosure**: Report vulnerabilities through proper channels

## 🧪 Testing

Test the scanner on your own systems or dedicated testing environments:

```bash
# Test on localhost
python scanner.py 127.0.0.1 -p 1-1000

# Test with verbose output
python scanner.py localhost -p 20-25 -v
```

## 🔧 Customization

The scanner can be easily extended with additional features:

- **Custom Service Signatures**: Add new service detection patterns
- **Additional Vulnerability Checks**: Expand the vulnerability database
- **Output Formats**: Add XML, CSV, or other report formats
- **Advanced Scanning**: Implement UDP scanning, OS detection

## 📚 Learning Outcomes

This project demonstrates:
- Network security fundamentals
- Python socket programming
- Concurrent programming techniques
- Security tool development
- Professional code documentation

## 🤝 Contributing

Contributions are welcome! Areas for improvement:
- Additional service detection signatures
- More vulnerability checks
- Performance optimizations
- Additional output formats

## ⚠️ Disclaimer

This tool is for educational and authorized testing purposes only. Users are responsible for ensuring they have proper authorization before scanning any systems. Unauthorized network scanning may be illegal in your jurisdiction.

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

**Author**: Adarsh Pratap Singh  
**Contact**: adarshsingh53152@gmail.com  
**Portfolio**: [adarsh-pratap-singh-portfolio.netlify.app](https://adarsh-pratap-singh-portfolio.netlify.app/)