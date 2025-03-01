# IP Addresses

## Basic Concepts

IP addresses are used for communication over Layer 3 of the OSI model (network layer). They enable routing of traffic across networks.

### IPv4
* Most commonly used format
* Uses decimal notation (e.g., 192.168.57.139)
* Made up of 32 bits (4 bytes) divided into four octets
* Each octet represents 8 bits with values from 0 to 255
* Limited address space (approximately 4.3 billion addresses)

### IPv6
* Newer format designed to address IPv4 address exhaustion
* Uses hexadecimal notation (e.g., fe80::215:5dff:fe00:1234)
* Made up of 128 bits
* Provides an extremely large address space (2^128 addresses)
* Despite availability, IPv4 remains more widely used

## Binary Representation

IP addresses are stored as binary (ones and zeros) in computers:
* Each octet in IPv4 represents 8 bits
* Values correspond to powers of 2: 128, 64, 32, 16, 8, 4, 2, 1
* Example: 192 in binary is 11000000

## Private vs Public IP Addresses

### Private IP Addresses
* Used within local networks
* Not routable on the internet
* Defined address ranges:
  * Class A: 10.0.0.0 to 10.255.255.255
  * Class B: 172.16.0.0 to 172.31.255.255
  * Class C: 192.168.0.0 to 192.168.255.255
* Most home networks use Class C (192.168.x.x)
* Large organizations often use Class A (10.x.x.x)

### Public IP Addresses
* Globally unique addresses
* Assigned by Internet Service Providers (ISPs)
* Used for routing traffic across the internet
* Limited resource (IPv4 exhaustion)

## Network Address Translation (NAT)

NAT allows multiple devices with private IP addresses to share a single public IP address:
* Resolves the IPv4 address shortage problem
* Allows many devices (e.g., 20+ in a home) to connect to the internet
* Works by translating between private and public addresses
* Implemented by routers and firewalls
* Example: All devices on a home network with private IPs communicate externally through a single public IP

## IP Address Classes

### Class A
* First bit is 0
* Range: 0.0.0.0 to 127.255.255.255
* Private range: 10.0.0.0 to 10.255.255.255
* Large number of hosts per network

### Class B
* First two bits are 10
* Range: 128.0.0.0 to 191.255.255.255
* Private range: 172.16.0.0 to 172.31.255.255
* Medium number of networks and hosts

### Class C
* First three bits are 110
* Range: 192.0.0.0 to 223.255.255.255
* Private range: 192.168.0.0 to 192.168.255.255
* Large number of networks with fewer hosts each
* Most common for home and small business networks

### Class D and E
* Exist but not covered in detail in this course
* Used for multicast and experimental purposes

## Commands for Viewing IP Configuration

* Linux: `ifconfig` or `ip addr`
* Windows: `ipconfig`

## Practical Implications for Ethical Hackers

* Understanding IP addressing helps identify network boundaries
* Recognizing private vs public addresses helps determine scope
* Class ranges provide insight into organization size and network design
* IP addresses are key targets for reconnaissance and scanning
* NAT can complicate external penetration testing

## CIDR Notation

CIDR (Classless Inter-Domain Routing) notation provides a more flexible way to specify IP address ranges than traditional class-based addressing.

### Basic Concept
* Expressed as an IP address followed by a slash and a number (e.g., 192.168.1.0/24)
* The number after the slash represents the number of bits used for the network portion
* Allows for more efficient allocation of IP addresses

### Examples
* 192.168.1.0/24 - Represents 256 IP addresses (192.168.1.0 to 192.168.1.255)
* 10.0.0.0/8 - Represents 16,777,216 IP addresses (10.0.0.0 to 10.255.255.255)
* 172.16.0.0/12 - Represents 1,048,576 IP addresses (172.16.0.0 to 172.31.255.255)

### CIDR in Penetration Testing
* Used to define target scopes precisely
* Helps identify potential network segments
* Critical for accurate network scanning and enumeration
* Essential for understanding firewall rules and access control lists

## Special-Use IP Addresses

### Localhost
* IP address: 127.0.0.1 (IPv4) or ::1 (IPv6)
* Used for communication within the same device
* Tests for services running locally
* Not routable outside the device

### Multicast Addresses
* Range: 224.0.0.0 to 239.255.255.255
* Used for one-to-many communication
* Often used for service discovery and streaming

### Broadcast Address
* Usually the last address in a subnet (e.g., 192.168.1.255 in a /24 network)
* Used to send packets to all devices on a network
* Often used in network reconnaissance

## IPv6 Adoption Challenges

Despite its benefits, IPv6 adoption has faced several challenges:

### Technical Challenges
* Lack of backward compatibility with IPv4
* Requires "dual-stack" implementations during transition
* Different security considerations compared to IPv4
* More complex address formats and subnetting

### Security Implications
* New attack vectors due to expanded address space
* Potential for reconnaissance difficulty (harder to scan)
* Built-in IPsec support, but implementation varies
* Transition mechanisms (tunneling, dual-stack) introduce security risks
* Many security tools still not fully IPv6-compatible

### Penetration Testing Considerations
* Need to test both IPv4 and IPv6 infrastructure
* Different scanning approaches required for IPv6 networks
* Special attention to transition mechanisms as potential vulnerabilities
* New IPv6-specific vulnerabilities like Router Advertisement spoofing

## Static vs. Dynamic IP Allocation

### Static IP Assignment
* Manually configured IP addresses
* Consistent across reboots
* Used for servers, network equipment, and critical infrastructure
* Easier to track and monitor
* Requires more administrative overhead

### Dynamic IP Assignment (DHCP)
* Automatically assigned IP addresses
* May change over time (leases)
* Used for client devices and general-purpose systems
* Reduces administrative overhead
* DHCP servers become critical infrastructure points

### Security Implications
* DHCP can be vulnerable to attacks like DHCP starvation and spoofing
* Static IPs create predictable targets for attackers
* Dynamic IPs can complicate tracking and monitoring
* DHCP logs are valuable for forensics and incident response