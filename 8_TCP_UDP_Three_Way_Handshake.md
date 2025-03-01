# TCP, UDP, & the Three-Way Handshake

## TCP vs. UDP

### TCP (Transmission Control Protocol)
* Layer 4 protocol (Transport layer)
* Connection-oriented protocol
* Provides high reliability
* Ensures data arrives completely and in order
* Used by protocols requiring reliable communication:
  * HTTP/HTTPS (websites)
  * SSH (secure shell)
  * FTP (file transfer)
  * SMTP (email)

### UDP (User Datagram Protocol)
* Layer 4 protocol (Transport layer)
* Connectionless protocol
* Faster but less reliable than TCP
* No guarantee of packet delivery or order
* Used by protocols where speed is more important than reliability:
  * DNS (domain name resolution)
  * Streaming services
  * VoIP (Voice over IP)
  * DHCP (dynamic host configuration)

## The Three-Way Handshake (TCP)

The three-way handshake is the process used to establish a TCP connection between two devices:

1. **SYN (Synchronize)**: Client sends a SYN packet to the server
   * "Hello, I want to connect to you"

2. **SYN-ACK (Synchronize-Acknowledge)**: Server responds with a SYN-ACK packet
   * "Hello, I acknowledge you and I'm ready to connect"

3. **ACK (Acknowledge)**: Client sends an ACK packet to the server
   * "I acknowledge your response, let's start communicating"

### Real-World Analogy
The instructor compares this to greeting a neighbor:
* SYN: You wave and say hello
* SYN-ACK: Your neighbor waves back
* ACK: You acknowledge and begin conversation

## Ports

* Ports are virtual endpoints for communication
* Range from 0 to 65,535
* Different services use specific port numbers
* Examples:
  * HTTP: Port 80
  * HTTPS: Port 443
  * SSH: Port 22
  * FTP: Port 21

### Connection Process with Ports
When connecting to a service:
1. Client sends SYN to a specific port (e.g., port 443 for HTTPS)
2. If port is open, server responds with SYN-ACK
3. Client sends ACK to establish connection
4. Data transfer begins

## Wireshark Demonstration

The instructor demonstrates the three-way handshake using Wireshark:
1. Captures network traffic
2. Identifies SYN packet: Client initiating connection to server
3. Identifies SYN-ACK packet: Server responding to client
4. Identifies ACK packet: Client acknowledging and completing connection

## Importance in Penetration Testing

Understanding TCP, UDP, and the three-way handshake is crucial for:

* **Network Scanning**: Different scanning techniques manipulate the three-way handshake
* **Port Scanning**: Determining which ports/services are available
* **Stealth Scanning**: Modifying the handshake for more discrete scanning
* **Service Identification**: Understanding which protocol a service uses
* **Exploitation**: Many exploits target specific TCP/UDP services

The instructor notes that this knowledge will be important when the course covers scanning techniques, as scanners manipulate the three-way handshake in various ways to discover open ports and services.

## TCP Flags and Their Significance

TCP packets contain various flags that control the connection state:

* **SYN (Synchronize)**: Initiates a connection
* **ACK (Acknowledge)**: Acknowledges received data
* **FIN (Finish)**: Graceful connection termination
* **RST (Reset)**: Abrupt connection termination
* **PSH (Push)**: Pushes data to the application without buffering
* **URG (Urgent)**: Indicates urgent data
* **ECE and CWR**: Used for explicit congestion notification

These flags are essential in various scanning techniques:
* SYN scan: Only sends SYN packets to identify open ports
* FIN scan: Sends FIN packets to evade certain firewall rules
* XMAS scan: Sets FIN, PSH, and URG flags to trigger specific responses

## The Four-Way TCP Teardown Process

While TCP connections are established using a three-way handshake, they are terminated with a four-way handshake:

1. **Client Initiates Termination**: 
   * Client sends a FIN packet
   * "I'm finished sending data"

2. **Server Acknowledges**:
   * Server responds with an ACK packet
   * "I acknowledge your finish"

3. **Server Initiates Its Termination**:
   * Server sends its own FIN packet
   * "I'm also finished sending data"

4. **Client Acknowledges**:
   * Client responds with an ACK packet
   * "I acknowledge your finish"

This four-way process ensures both sides have a chance to complete any pending transmission before the connection is fully closed.

### TIME_WAIT State

After the four-way handshake, the client enters a TIME_WAIT state:
* Typically lasts for twice the Maximum Segment Lifetime (MSL)
* Ensures any delayed packets are properly handled
* Prevents potential issues with new connections using the same ports

### Security Implications

Understanding the TCP teardown process helps in:
* Identifying incomplete or abnormal connection terminations
* Detecting potential DoS attacks targeting connection states
* Understanding network behavior during port scans
* Analyzing network logs for suspicious connection patterns

## TCP Window Sizing and Flow Control

TCP uses windowing to control the flow of data:

### Basic Concept
* The "window size" determines how many bytes can be sent before requiring an acknowledgment
* Helps optimize network throughput while preventing congestion
* Dynamically adjusted based on network conditions

### Window Scaling
* Allows for window sizes larger than the 16-bit field in the TCP header
* Essential for high-bandwidth, high-latency networks
* Set during the initial three-way handshake

### Security Implications
* Window size manipulation can be used for fingerprinting operating systems
* Zero-window attacks can cause denial of service
* Window size analysis can reveal network performance issues

## Security Implications: TCP vs. UDP

Understanding the security trade-offs between TCP and UDP is crucial:

### TCP Security Considerations
* **Advantages**:
  * Connection-oriented nature provides accountability
  * Sequence numbers help prevent replay attacks
  * Three-way handshake can limit certain DoS attacks
  
* **Vulnerabilities**:
  * SYN flood attacks target the three-way handshake
  * Session hijacking through sequence number prediction
  * Resource exhaustion from maintaining connection state

### UDP Security Considerations
* **Advantages**:
  * Simpler, with less overhead
  * Less susceptible to state-based attacks
  
* **Vulnerabilities**:
  * More easily spoofed due to connectionless nature
  * Often used in amplification/reflection DDoS attacks
  * No built-in mechanism to prevent packet replay

### Penetration Testing Approaches
* Different scanning techniques for TCP vs. UDP services
* Service-specific vulnerabilities often correspond to the protocol used
* Protocol selection can impact the success of various attack techniques