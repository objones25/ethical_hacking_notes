# Common Network Commands

## Overview
This section covers essential network commands used during penetration testing and ethical hacking activities. These commands help with network discovery, connectivity testing, and information gathering.

## IP Configuration Commands

### Windows
- `ipconfig` - Display IP configuration information
- `ipconfig /all` - Display detailed IP configuration including MAC addresses, DNS servers, etc.
- `ipconfig /release` - Release current IP address
- `ipconfig /renew` - Request new IP address from DHCP
- `ipconfig /flushdns` - Clear DNS resolver cache

### Linux
- `ifconfig` - Display network interface information (older command)
- `ip addr` or `ip a` - Modern replacement for ifconfig
- `ip link` - Show network interfaces 
- `ip route` or `ip r` - Display routing table

## Network Discovery and Analysis

### Ping
- `ping [hostname/IP]` - Test connectivity to remote host
  - Example: `ping 8.8.8.8` or `ping google.com`
  - Options: `-c` (count in Linux), `-n` (count in Windows)

### Traceroute
- Windows: `tracert [hostname/IP]`
- Linux: `traceroute [hostname/IP]`
- Purpose: Shows the route packets take to reach a destination

### ARP Commands
- `arp -a` - Display ARP cache (maps IP addresses to MAC addresses)
- `ip neigh` - Linux equivalent to show neighbor table

## DNS Commands

### nslookup
- `nslookup [hostname]` - Query DNS for IP address of hostname
- `nslookup -type=MX [domain]` - Query for mail exchange records
- `nslookup -type=NS [domain]` - Query for name server records

### dig (Linux)
- `dig [hostname]` - More detailed DNS lookup
- `dig MX [domain]` - Query for mail exchange records
- `dig NS [domain]` - Query for name server records

## Port and Service Discovery

### netstat
- `netstat -ano` (Windows) - List all connections and listening ports
- `netstat -tuln` (Linux) - List TCP/UDP listening ports
- `netstat -r` - Display routing table

### ss (Linux)
- `ss -tuln` - Modern replacement for netstat, shows listening ports

## Network Scanning Tools

### nmap
- Basic syntax: `nmap [target]`
- Common options:
  - `-sS` - SYN scan (stealthy)
  - `-sV` - Service/version detection
  - `-O` - OS detection
  - `-p 1-1000` - Scan specific port range
  - `-A` - Aggressive scan (OS detection, version detection, script scanning)

### Examples
```bash
# Scan a single host for open ports
nmap 192.168.1.1

# Scan a network range
nmap 192.168.1.0/24

# Service version detection
nmap -sV 192.168.1.10

# Full scan with OS detection
nmap -A 192.168.1.10
```

## Wireless Network Commands (Linux)

- `iwconfig` - Display wireless network interface information
- `iwlist [interface] scan` - Scan for wireless networks
- `airmon-ng` - List wireless interfaces
- `airmon-ng start [interface]` - Start monitor mode

## File Transfer and Network Services

- `wget [URL]` - Download files from the web
- `curl [URL]` - Transfer data from or to a server
- `scp [file] [user@host:/path]` - Secure copy between hosts
