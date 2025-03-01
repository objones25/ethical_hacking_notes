# Common Ports & Protocols

## TCP Ports

| Port | Protocol | Description |
|------|----------|-------------|
| 21 | FTP (File Transfer Protocol) | Used to transfer files between client and server. Allows you to put files on a server or get files from a server. |
| 22 | SSH (Secure Shell) | Encrypted version of Telnet. Used for secure remote login to machines. |
| 23 | Telnet | Used for remote login to machines (unencrypted). |
| 25 | SMTP (Simple Mail Transfer Protocol) | Used for sending email. |
| 53 | DNS (Domain Name System) | Translates domain names to IP addresses. Can use both TCP and UDP. |
| 80 | HTTP (Hypertext Transfer Protocol) | Used for unencrypted web browsing. |
| 110 | POP3 (Post Office Protocol v3) | Used for retrieving email. |
| 139 | SMB/NetBIOS | Used for file sharing on Windows networks. |
| 143 | IMAP (Internet Message Access Protocol) | Used for email retrieval. |
| 443 | HTTPS (HTTP Secure) | Encrypted version of HTTP. Used for secure web browsing. |
| 445 | SMB (Server Message Block) | Modern version of SMB direct over TCP/IP. Used for file sharing in Windows environments. Common target for exploits like EternalBlue (MS17-010) and WannaCry ransomware. |

## Additional Important TCP Ports

| Port | Protocol | Description |
|------|----------|-------------|
| 135 | MSRPC | Microsoft Remote Procedure Call, used for Windows services communication |
| 389 | LDAP | Lightweight Directory Access Protocol, used for directory services |
| 1433 | MSSQL | Microsoft SQL Server database service |
| 3306 | MySQL | MySQL database service |
| 3389 | RDP | Remote Desktop Protocol, used for remote control of Windows systems |
| 5432 | PostgreSQL | PostgreSQL database service |
| 5900 | VNC | Virtual Network Computing, for remote desktop access |
| 5985/5986 | WinRM | Windows Remote Management (HTTP/HTTPS) |
| 8080 | HTTP Alternate | Commonly used for web proxies, web caches, and web applications |
| 8443 | HTTPS Alternate | Secure alternate port for HTTPS |

## UDP Ports

| Port | Protocol | Description |
|------|----------|-------------|
| 53 | DNS (Domain Name System) | Translates domain names to IP addresses. Uses both UDP and TCP. |
| 67/68 | DHCP (Dynamic Host Configuration Protocol) | Assigns IP addresses to devices on a network. |
| 69 | TFTP (Trivial File Transfer Protocol) | Simplified version of FTP that uses UDP instead of TCP. |
| 161 | SNMP (Simple Network Management Protocol) | Used for network management. Can contain valuable information if default community strings like "public" are in use. |

## Additional Important UDP Ports

| Port | Protocol | Description |
|------|----------|-------------|
| 123 | NTP | Network Time Protocol, used for clock synchronization |
| 137-139 | NetBIOS | NetBIOS Name Service, important for legacy Windows networking |
| 389 | LDAP | Lightweight Directory Access Protocol (also uses UDP) |
| 500 | IKE | Internet Key Exchange for IPsec |
| 1434 | MSSQL | Microsoft SQL Server browser service |
| 5353 | mDNS | Multicast DNS, used for local network service discovery |

## Port Categories

Ports are divided into three ranges:

- **Well-Known Ports (0-1023)**: Assigned by IANA, require administrative privileges to use
- **Registered Ports (1024-49151)**: Registered with IANA but can be used by ordinary users
- **Dynamic/Private Ports (49152-65535)**: Used for client-side connections, allocated dynamically

## Security Implications

- **SMB (139/445)**: Primary target for many attacks including the infamous WannaCry ransomware using the EternalBlue exploit (MS17-010). SMB is frequently open on networks and has a history of critical vulnerabilities.

- **SSH (22)** and **Telnet (23)**: Telnet sends all data in cleartext while SSH is encrypted. Always prefer SSH over Telnet.

- **HTTP (80)** vs **HTTPS (443)**: HTTP is unencrypted and not secure, while HTTPS provides encryption. Most websites now use HTTPS by default.

- **RDP (3389)**: Frequently targeted for brute force attacks and known vulnerabilities. Exposure to the internet is dangerous.

- **Database Ports (1433, 3306, 5432)**: Direct access to database ports from untrusted networks can lead to data breaches and should be restricted.

- **LDAP (389)**: Can leak sensitive directory information if not properly secured.

- **SNMP (161)**: Older versions (v1, v2) have weak authentication. Default community strings (public/private) are commonly exploited.

## Penetration Testing Perspective

As a penetration tester, memorizing these common ports is essential. When scanning a target, you should immediately recognize what services are running based on open ports. For example:

- Port 21 open → FTP service available, may allow anonymous login
- Ports 139/445 open → SMB file sharing, potential for lateral movement
- Port 80/443 open → Web server, potential for web application vulnerabilities
- Port 3389 open → RDP service, potential for brute force or exploitation
- Database ports open → Potential for direct database access, default credentials

When scanning, you will primarily focus on TCP ports, but UDP services like DNS and SNMP can also provide valuable information or attack vectors.

## Port Scanning Techniques

### Using Nmap

Nmap (Network Mapper) is the most popular tool for port scanning and network reconnaissance. Here are common scanning techniques:

#### TCP SYN Scan (Half-open Scanning)
```bash
nmap -sS <target>
```
- Fastest and most popular scan
- Doesn't complete the TCP handshake
- Can be stealthy as connections aren't fully established

#### TCP Connect Scan
```bash
nmap -sT <target>
```
- Completes the full TCP handshake
- Less stealthy but more reliable
- Used when SYN scanning isn't possible

#### UDP Scan
```bash
nmap -sU <target>
```
- Scans for open UDP ports
- Typically slower than TCP scanning
- Often overlooked but critical for comprehensive testing

#### Service Version Detection
```bash
nmap -sV <target>
```
- Detects specific versions of services running on ports
- Critical for identifying vulnerable services

#### OS Detection
```bash
nmap -O <target>
```
- Attempts to identify the operating system
- Useful for targeting specific OS vulnerabilities

#### Comprehensive Scan
```bash
nmap -sC -sV -O -p- <target>
```
- `-sC`: Default scripts
- `-sV`: Service version detection
- `-O`: OS detection
- `-p-`: All ports (1-65535)

## Securing Common Ports

### General Security Practices
- Disable unnecessary services and close unused ports
- Implement strong authentication for all services
- Use firewalls to restrict access to specific IPs or networks
- Implement intrusion detection/prevention systems (IDS/IPS)
- Regularly update and patch services

### Service-Specific Recommendations

- **FTP (21)**: Use SFTP (SSH File Transfer) or FTPS (FTP Secure) instead
- **SSH (22)**: Use key-based authentication, disable root login, change default port
- **Telnet (23)**: Avoid entirely, use SSH instead
- **SMTP (25)**: Implement SPF, DKIM, and DMARC for email security
- **HTTP/HTTPS (80/443)**: Use a web application firewall, force HTTPS
- **SMB (445)**: Block at the firewall if external access isn't needed, keep updated
- **RDP (3389)**: Use a VPN, implement Network Level Authentication, change default port

## Detecting Port Scans

Signs of port scanning activity:
- Large number of connection attempts in a short period
- Connection attempts to multiple ports in sequence
- Half-open connections (SYN without completion)
- Connections from unusual geographic locations

Defensive measures:
- Configure firewalls to detect and block scanning patterns
- Implement rate limiting for connection attempts
- Use port knocking or single packet authorization for sensitive services
- Deploy a honeypot to detect and analyze scanning activity