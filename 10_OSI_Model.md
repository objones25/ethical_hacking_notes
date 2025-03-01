# The OSI Model

## Overview

The OSI (Open Systems Interconnection) Model is a conceptual framework that standardizes the functions of a communication system into seven abstraction layers. It helps in understanding network communication and troubleshooting by breaking down complex network interactions into more manageable parts.

## Mnemonic to Remember the Layers

"Please Do Not Throw Sausage Pizza Away" (from top to bottom)

| Number | Layer | Mnemonic | Description |
|--------|-------|----------|-------------|
| 7 | Application | Pizza | User interaction layer (HTTP, SMTP, FTP) |
| 6 | Presentation | Sausage | Data format translation, encryption (JPEG, MPEG, GIF) |
| 5 | Session | Throw | Manages sessions between applications |
| 4 | Transport | Not | End-to-end connections, reliability (TCP, UDP) |
| 3 | Network | Do | Logical addressing and routing (IP) |
| 2 | Data Link | Please | Physical addressing (MAC addresses, switching) |
| 1 | Physical | Away | Physical media, cables, electrical signals |

## Layer Details

### 1. Physical Layer
- Deals with the physical connection between devices
- Examples: Cables, hubs, repeaters
- Includes specifications for cables, pins, voltages
- Raw bit stream transmission

### 2. Data Link Layer
- Provides node-to-node data transfer between two directly connected nodes
- Handles MAC addresses (media access control)
- Switching occurs at this layer
- Error detection and correction
- Examples: Ethernet, Wi-Fi

### 3. Network Layer
- Provides routing functionality
- Handles IP addresses
- Determines paths for data to travel
- Examples: Routers, IP (IPv4, IPv6)

### 4. Transport Layer
- End-to-end communication 
- Controls reliability of communication through:
  - Flow control
  - Segmentation/desegmentation
  - Error control
- Examples: TCP (connection-oriented), UDP (connectionless)
- TCP uses the three-way handshake (SYN, SYN-ACK, ACK)

### 5. Session Layer
- Manages sessions between applications
- Sets up, coordinates, and terminates conversations
- Examples: NetBIOS, RPC

### 6. Presentation Layer
- Data translation, encryption, and compression
- Converts data from the application layer into a format for transmission
- Examples: JPEG, MPEG, GIF, encryption protocols

### 7. Application Layer
- Closest to the end user
- User interfaces and application functionality
- Examples: HTTP, SMTP, FTP, DNS

## Troubleshooting with the OSI Model

When troubleshooting network issues, it's best to start at Layer 1 (Physical) and work your way up to Layer 7 (Application):

1. **Physical (Layer 1)**: "Is the cable plugged in? Are there lights on the network interface?"
2. **Data Link (Layer 2)**: "Is the switch working? Is the MAC address recognized?"
3. **Network (Layer 3)**: "Do we have an IP address? Can we reach the gateway?"
4. **Transport (Layer 4)**: "Are the required ports open? Is TCP handshaking properly?"
5. **Session/Presentation/Application (Layers 5-7)**: "Is the application configured correctly?"

## Practical Application in Penetration Testing

- **Layer 2 attacks**: MAC flooding, ARP poisoning, VLAN hopping
- **Layer 3 attacks**: IP spoofing, routing attacks
- **Layer 4 attacks**: TCP SYN floods, port scanning
- **Layer 7 attacks**: SQL injection, XSS, application vulnerabilities

Understanding the OSI model helps penetration testers communicate effectively with network engineers and identify vulnerabilities at specific layers of network communication.

## Common Terminology in Professional Settings

Network professionals often refer to layers rather than specific components:
- "We have a Layer 2 issue" (switching or MAC address problem)
- "The problem is at Layer 3" (routing or IP addressing issue)
- "It's a Layer 7 problem" (application configuration issue)

Many network devices operate at multiple layers:
- Home routers are typically Layer 2/3 devices (they do both switching and routing)
