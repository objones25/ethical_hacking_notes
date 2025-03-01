# Building a Port Scanner

## Overview

A port scanner is a fundamental tool for ethical hackers that allows the discovery of open ports on target systems. Open ports indicate services that may be vulnerable to exploitation. This document covers how to build a simple port scanner using Python and sockets.

## Basic Port Scanner Concepts

### What a Port Scanner Does
- Attempts to connect to ports on a target system
- Determines which ports are open, closed, or filtered
- Identifies potential services running on those ports
- Provides initial reconnaissance information for further testing

### Port States
- **Open**: Port is accessible and a service is listening
- **Closed**: Port is accessible but no service is listening
- **Filtered**: Firewall or filter is blocking the port
- **Unfiltered**: Port is accessible but state cannot be determined

## Simple Port Scanner Implementation

### Basic Scanner Functions

```python
import socket
import sys
from datetime import datetime

# Simple port scanner function
def scan_port(target, port):
    try:
        # Create socket object
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Set timeout for connection attempt
        s.settimeout(1)
        
        # Attempt to connect to the port
        result = s.connect_ex((target, port))
        
        # Close the socket
        s.close()
        
        # Return True if port is open (result == 0)
        return result == 0
    
    except socket.error:
        return False

# Function to scan a range of ports
def scan_ports(target, start_port, end_port):
    print(f"Starting scan on host: {target}")
    print(f"Time started: {datetime.now()}")
    print("-" * 50)
    
    # Track open ports
    open_ports = []
    
    # Scan each port in the range
    for port in range(start_port, end_port + 1):
        print(f"Scanning port {port}...", end="\r")
        sys.stdout.flush()
        
        if scan_port(target, port):
            open_ports.append(port)
            print(f"Port {port}: Open      ")
    
    print("\nScan completed!")
    print(f"Time finished: {datetime.now()}")
    print("-" * 50)
    
    # Summary of open ports
    if open_ports:
        print("Open ports:")
        for port in open_ports:
            print(f"- Port {port}")
    else:
        print("No open ports found.")
    
    return open_ports
```

### Main Function for the Scanner

```python
def main():
    # Get target from user
    target = input("Enter target IP address: ")
    
    # Validate IP address format
    try:
        socket.inet_aton(target)
    except socket.error:
        # If not a valid IP, try to resolve the hostname
        try:
            target = socket.gethostbyname(target)
            print(f"Hostname resolved to: {target}")
        except socket.gaierror:
            print("Error: Invalid hostname or IP address")
            return
    
    # Get port range from user
    try:
        start_port = int(input("Enter starting port (default 1): ") or "1")
        end_port = int(input("Enter ending port (default 1024): ") or "1024")
        
        if start_port < 1 or end_port > 65535 or start_port > end_port:
            print("Error: Invalid port range. Use ports 1-65535.")
            return
            
    except ValueError:
        print("Error: Ports must be numeric values")
        return
    
    # Perform the scan
    scan_ports(target, start_port, end_port)

if __name__ == "__main__":
    main()
```

## Enhanced Port Scanner With Service Detection

### Service Detection Function

```python
def detect_service(target, port):
    try:
        # Create socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((target, port))
        
        # Send empty string to prompt for banner
        s.send(b'')
        
        # Receive banner (if any)
        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
        s.close()
        
        return banner
    except:
        return None
```

### Known Ports Dictionary

```python
# Common ports and their services
common_ports = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPC",
    135: "RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1723: "PPTP",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC",
    8080: "HTTP Proxy"
}
```

### Enhanced Scanning Function

```python
def enhanced_scan_ports(target, start_port, end_port):
    print(f"Starting enhanced scan on host: {target}")
    print(f"Time started: {datetime.now()}")
    print("-" * 60)
    
    # Track open ports with service info
    open_ports = {}
    
    # Scan each port in the range
    for port in range(start_port, end_port + 1):
        print(f"Scanning port {port}...", end="\r")
        sys.stdout.flush()
        
        if scan_port(target, port):
            # Attempt service detection
            banner = detect_service(target, port)
            
            # Get known service name (if available)
            service = common_ports.get(port, "Unknown")
            
            # Store information
            open_ports[port] = {
                "service": service,
                "banner": banner
            }
            
            # Print immediate results
            print(f"Port {port}: Open - {service}      ")
    
    print("\nScan completed!")
    print(f"Time finished: {datetime.now()}")
    print("-" * 60)
    
    # Summary of open ports
    if open_ports:
        print("\nDetailed Results:")
        print("-" * 60)
        print(f"{'Port':<8} {'Service':<15} {'Banner':<30}")
        print("-" * 60)
        
        for port, info in open_ports.items():
            banner_text = info['banner'] if info['banner'] else "No banner"
            if len(banner_text) > 30:
                banner_text = banner_text[:27] + "..."
            
            print(f"{port:<8} {info['service']:<15} {banner_text:<30}")
    else:
        print("No open ports found.")
    
    return open_ports
```

## Multithreaded Port Scanner

### Threading Implementation

```python
import threading
import queue

def threaded_scan(target, ports_queue, open_ports, thread_lock):
    while not ports_queue.empty():
        try:
            # Get port from queue
            port = ports_queue.get(block=False)
            
            # Scan the port
            if scan_port(target, port):
                # Attempt service detection
                banner = detect_service(target, port)
                
                # Get known service name (if available)
                service = common_ports.get(port, "Unknown")
                
                # Use lock when updating shared resources
                with thread_lock:
                    open_ports[port] = {
                        "service": service,
                        "banner": banner
                    }
                    print(f"Port {port}: Open - {service}")
        
        except queue.Empty:
            break

def multi_threaded_scan(target, start_port, end_port, num_threads=10):
    print(f"Starting multi-threaded scan on host: {target}")
    print(f"Time started: {datetime.now()}")
    print(f"Using {num_threads} threads")
    print("-" * 60)
    
    # Create a queue of ports to scan
    ports_queue = queue.Queue()
    for port in range(start_port, end_port + 1):
        ports_queue.put(port)
    
    # Shared dictionary for open ports and lock for thread safety
    open_ports = {}
    thread_lock = threading.Lock()
    
    # Create and start threads
    threads = []
    for _ in range(num_threads):
        thread = threading.Thread(
            target=threaded_scan,
            args=(target, ports_queue, open_ports, thread_lock)
        )
        thread.start()
        threads.append(thread)
    
    # Wait for all threads to finish
    for thread in threads:
        thread.join()
    
    print("\nScan completed!")
    print(f"Time finished: {datetime.now()}")
    print("-" * 60)
    
    # Summary of open ports
    if open_ports:
        print("\nDetailed Results:")
        print("-" * 60)
        print(f"{'Port':<8} {'Service':<15} {'Banner':<30}")
        print("-" * 60)
        
        for port, info in sorted(open_ports.items()):
            banner_text = info['banner'] if info['banner'] else "No banner"
            if len(banner_text) > 30:
                banner_text = banner_text[:27] + "..."
            
            print(f"{port:<8} {info['service']:<15} {banner_text:<30}")
    else:
        print("No open ports found.")
    
    return open_ports
```

## Advanced Scanning Techniques

### SYN Scan Implementation (Requires Raw Sockets)

```python
def syn_scan(target, port):
    # Note: This requires administrative privileges
    try:
        # Create raw socket
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        
        # Construct SYN packet
        # This is a simplified example - real implementation requires packet crafting
        # Use libraries like Scapy for actual implementation
        
        # Send SYN packet
        # Listen for SYN-ACK response
        
        # If SYN-ACK received, port is open
        # Don't complete handshake - just note port as open
        
        return True  # If port is open
    
    except:
        return False
```

### Implementing Different Scan Types

```python
def scan_port_with_type(target, port, scan_type="connect"):
    """
    Scan a port using different techniques
    
    scan_type options:
    - "connect": Full TCP connection (default)
    - "syn": SYN scan (requires admin privileges)
    - "fin": FIN scan (requires admin privileges)
    - "null": NULL scan (requires admin privileges)
    - "xmas": XMAS scan (requires admin privileges)
    - "udp": UDP scan
    """
    
    if scan_type == "connect":
        # Regular TCP connect scan
        return scan_port(target, port)
    
    elif scan_type == "syn":
        # SYN scan requires administrative privileges
        return syn_scan(target, port)
    
    elif scan_type == "udp":
        # UDP scan
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(1)
            s.sendto(b'', (target, port))
            data, addr = s.recvfrom(1024)
            s.close()
            return True
        except:
            return False
    
    # Other scan types would be implemented here
    
    else:
        print(f"Scan type '{scan_type}' not implemented")
        return False
```

## Full Port Scanner with Command Line Arguments

### Complete Scanner with Options

```python
import socket
import sys
import threading
import queue
import argparse
from datetime import datetime

def main():
    # Set up command line argument parsing
    parser = argparse.ArgumentParser(description='Python Port Scanner')
    
    parser.add_argument('target', help='Target IP address or hostname')
    parser.add_argument('-p', '--ports', default='1-1024', help='Port range to scan (default: 1-1024)')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('-s', '--scan-type', choices=['connect', 'syn', 'udp'], 
                        default='connect', help='Scan type (default: connect)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    
    args = parser.parse_args()
    
    # Process target
    try:
        target_ip = socket.gethostbyname(args.target)
        print(f"Target: {args.target} ({target_ip})")
    except socket.gaierror:
        print(f"Error: Could not resolve hostname {args.target}")
        sys.exit(1)
    
    # Process port range
    try:
        if '-' in args.ports:
            start_port, end_port = map(int, args.ports.split('-'))
        elif ',' in args.ports:
            ports = [int(p) for p in args.ports.split(',')]
            start_port, end_port = min(ports), max(ports)
        else:
            start_port = end_port = int(args.ports)
        
        if start_port < 1 or end_port > 65535:
            print("Error: Ports must be between 1 and 65535")
            sys.exit(1)
    except ValueError:
        print("Error: Invalid port specification")
        sys.exit(1)
    
    # Run the appropriate scan
    if args.threads > 1:
        multi_threaded_scan(target_ip, start_port, end_port, args.threads)
    else:
        if args.scan_type == 'connect':
            scan_ports(target_ip, start_port, end_port)
        else:
            print(f"Running {args.scan_type} scan...")
            # Implement other scan types as needed
            
if __name__ == "__main__":
    main()
```

## Practical Usage and Applications

### Use Cases for Port Scanners
- Network reconnaissance during pentests
- Identifying potentially vulnerable services
- Validating firewall configurations
- Network inventory and asset management
- Security assessments and compliance checks

### Limitations and Considerations
- Port scanning may be detected by security systems
- Some network configurations may give false results
- Admin privileges required for certain scan types
- Legal implications - always get proper authorization
- Performance impact on network and target systems

### Best Practices
- Always obtain proper authorization before scanning
- Start with smaller port ranges and fewer threads
- Use appropriate scan types for the situation
- Document your findings thoroughly
- Combine with other recon tools for better results

## Extending the Port Scanner

### Additional Features to Implement
- OS fingerprinting
- Version detection for services
- Vulnerability checking against found services
- Scan multiple targets or network ranges
- Export results to various formats (CSV, JSON, HTML)
- Graphical user interface

### Integration with Other Tools
- Pass results to Nmap for deeper analysis
- Feed open ports to Metasploit for exploitation
- Save results to a database for tracking
- Integrate with reporting tools for documentation

## Example Complete Port Scanner

```python
#!/usr/bin/env python3
"""
Multi-threaded Port Scanner
---------------------------
A simple but effective port scanner with multiple scan types
and service detection capabilities.
"""

import socket
import sys
import threading
import queue
import argparse
import time
from datetime import datetime

# Common ports dictionary
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPC",
    135: "RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1723: "PPTP",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC",
    8080: "HTTP Proxy"
}

def scan_port(target, port, timeout=1):
    """Scan a single port using TCP connect method"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((target, port))
        s.close()
        return result == 0
    except Exception as e:
        print(f"Error scanning port {port}: {e}")
        return False

def detect_service(target, port, timeout=2):
    """Attempt to detect the service running on an open port"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target, port))
        
        # Try to get banner
        s.send(b'')
        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
        s.close()
        
        return banner
    except:
        return None

def worker(target, queue, results, lock, timeout=1):
    """Worker function for threaded scanning"""
    while not queue.empty():
        try:
            port = queue.get_nowait()
            if scan_port(target, port, timeout):
                service_name = COMMON_PORTS.get(port, "Unknown")
                banner = detect_service(target, port)
                
                with lock:
                    results[port] = {
                        "service": service_name,
                        "banner": banner
                    }
                    print(f"Port {port}: Open - {service_name}")
        except queue.Empty:
            break
        except Exception as e:
            print(f"Error in worker: {e}")

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="Python Port Scanner")
    
    # Required arguments
    parser.add_argument("target", help="Target IP address or hostname")
    
    # Optional arguments
    parser.add_argument("-p", "--ports", default="1-1024", 
                        help="Port range to scan (e.g., '1-1024', '80,443,8080')")
    parser.add_argument("-t", "--threads", type=int, default=10,
                        help="Number of threads (default: 10)")
    parser.add_argument("--timeout", type=float, default=1.0,
                        help="Timeout for connections in seconds (default: 1.0)")
    parser.add_argument("-o", "--output", help="Output file for results")
    parser.add_argument("-v", "--verbose", action="store_true", 
                        help="Enable verbose output")
    
    args = parser.parse_args()
    
    # Resolve target
    try:
        target_ip = socket.gethostbyname(args.target)
        print(f"Scanning {args.target} ({target_ip})")
    except socket.gaierror:
        print(f"Error: Could not resolve {args.target}")
        return
    
    # Parse port range
    try:
        if '-' in args.ports:
            start_port, end_port = map(int, args.ports.split('-'))
            ports = range(start_port, end_port + 1)
        elif ',' in args.ports:
            ports = [int(p) for p in args.ports.split(',')]
        else:
            try:
                port = int(args.ports)
                ports = [port]
            except ValueError:
                print("Error: Invalid port specification")
                return
    except ValueError:
        print("Error: Invalid port range")
        return
    
    # Prepare for scanning
    port_queue = queue.Queue()
    for port in ports:
        if 1 <= port <= 65535:
            port_queue.put(port)
    
    results = {}
    lock = threading.Lock()
    
    # Start timer
    start_time = time.time()
    print(f"Started scanning at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Scanning {port_queue.qsize()} ports with {args.threads} threads")
    
    # Create and start threads
    threads = []
    for _ in range(min(args.threads, port_queue.qsize())):
        t = threading.Thread(target=worker, args=(target_ip, port_queue, results, lock, args.timeout))
        threads.append(t)
        t.start()
    
    # Wait for all threads to finish
    for t in threads:
        t.join()
    
    # Calculate scan time
    scan_time = time.time() - start_time
    
    # Display results
    print("\nScan Results")
    print("-" * 60)
    if results:
        print(f"Found {len(results)} open ports on {args.target} ({target_ip})")
        print(f"{'Port':<8} {'Service':<15} {'Banner':<30}")
        print("-" * 60)
        
        for port in sorted(results.keys()):
            info = results[port]
            banner = info['banner'] if info['banner'] else "No banner"
            if len(banner) > 30:
                banner = banner[:27] + "..."
            print(f"{port:<8} {info['service']:<15} {banner:<30}")
    else:
        print(f"No open ports found on {args.target} ({target_ip})")
    
    print("-" * 60)
    print(f"Scan completed in {scan_time:.2f} seconds")
    
    # Write results to file if specified
    if args.output:
        try:
            with open(args.output, 'w') as f:
                f.write(f"Scan Results for {args.target} ({target_ip})\n")
                f.write(f"Scan completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("-" * 60 + "\n")
                
                if results:
                    f.write(f"Found {len(results)} open ports\n\n")
                    f.write(f"{'Port':<8} {'Service':<15} {'Banner':<30}\n")
                    f.write("-" * 60 + "\n")
                    
                    for port in sorted(results.keys()):
                        info = results[port]
                        banner = info['banner'] if info['banner'] else "No banner"
                        f.write(f"{port:<8} {info['service']:<15} {banner}\n")
                else:
                    f.write("No open ports found\n")
                
                f.write("-" * 60 + "\n")
                f.write(f"Scan completed in {scan_time:.2f} seconds\n")
            
            print(f"Results saved to {args.output}")
        except Exception as e:
            print(f"Error writing to output file: {e}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        sys.exit(1)
```

## Additional Resources for Learning More About Port Scanning

### Resources
- [Nmap Documentation](https://nmap.org/book/)
- [Python Socket Programming Documentation](https://docs.python.org/3/library/socket.html)
- [Scapy Documentation](https://scapy.readthedocs.io/) for advanced packet crafting
- [PortSwigger Port Scanner Tutorial](https://portswigger.net/burp/documentation/scanner)
- [Metasploit Scanner Modules](https://www.offensive-security.com/metasploit-unleashed/port-scanning/)
