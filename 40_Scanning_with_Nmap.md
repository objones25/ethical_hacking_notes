# Scanning with Nmap

## Introduction to Nmap

Nmap (Network Mapper) is an open-source utility for network discovery and security auditing. It's one of the most essential tools for penetration testers.

## Finding the Target Machine

Before scanning, you need to find the target's IP address.

### Using netdiscover
```bash
ifconfig  # Note your IP address (e.g., 192.168.57.139)
netdiscover -r 192.168.57.0/24  # Scan the subnet
```

### Using arp-scan
```bash
arp-scan -l
```
Look for the VMware MAC address.

## Understanding TCP Stealth Scanning

Nmap's default scanning method uses a technique called TCP SYN scanning, also known as "stealth scanning":

1. **Normal TCP Connection**: SYN → SYN-ACK → ACK
2. **Stealth Scan**: SYN → SYN-ACK → RST

The "stealth" aspect comes from never completing the connection:
- Send SYN packet to target port
- If port is open, receive SYN-ACK
- Instead of completing with ACK, send RST to terminate
- This approach leaves fewer logs on target systems

## Basic Nmap Scanning Syntax

```bash
nmap -T4 -p- -A <target_ip>
```

### Breaking Down the Command

- **nmap**: The command itself
- **-T4**: Timing template (0-5, higher is faster)
- **-p-**: Scan all 65535 ports (instead of just top 1000)
- **-A**: Enable OS detection, version detection, script scanning, and traceroute

## Interpreting Nmap Results

The scan provides several types of information:

### Open Ports
```
22/tcp   open   ssh        OpenSSH 2.9p2 (Protocol 1.99)
80/tcp   open   http       Apache httpd 1.3.20 ((Unix) PHP/4.3.7 mod_ssl/2.8.4 OpenSSL/0.9.6b)
139/tcp  open   netbios-ssn Samba smbd (workgroup: MYGROUP)
443/tcp  open   ssl/https  Apache/1.3.20 (Unix) PHP/4.3.7 mod_ssl/2.8.4 OpenSSL/0.9.6b
```

For each open port, Nmap shows:
1. Port number and protocol
2. State (open, closed, filtered)
3. Service name
4. Version information (when available)

### OS Detection
```
Device type: general purpose
Running: Linux 2.4.X
OS details: Linux 2.4.9 - 2.4.18 (likely embedded)
```

### Service Version Information
This information is critical for finding vulnerabilities in specific software versions.

## Common Nmap Options

### Basic Scan Types
- **-sS**: TCP SYN scan (default)
- **-sU**: UDP scan
- **-sV**: Version detection
- **-O**: OS detection
- **-sC**: Script scanning using default scripts

### Port Selection
- **-p-**: All ports (1-65535)
- **-p 1-1000**: Port range
- **-p 22,80,443**: Specific ports
- **--top-ports 1000**: Most common ports

### Performance
- **-T0** to **-T5**: Timing templates (higher is faster but noisier)
- **--min-rate \<number\>**: Minimum packets per second
- **--max-retries \<number\>**: Maximum retransmissions

### Output Options
- **-oN \<file\>**: Normal output to file
- **-oX \<file\>**: XML output to file
- **-oG \<file\>**: Grepable output to file
- **-v**: Increase verbosity

## Practical Scanning Strategy

### Two-Pass Approach (for efficiency)
1. Quick initial scan:
   ```bash
   nmap -T4 -p- <target_ip>
   ```

2. Detailed scan of open ports:
   ```bash
   nmap -T4 -A -p 22,80,139,443 <target_ip>
   ```

### UDP Scanning
```bash
nmap -sU <target_ip>
```
Note: UDP scanning is much slower than TCP scanning, so consider limiting to top ports:
```bash
nmap -sU --top-ports 100 <target_ip>
```

## Saving Scan Results

Always save Nmap results for documentation and further analysis:

```bash
nmap -T4 -p- -A <target_ip> -oN kioptrix_scan.txt
```

## Prioritizing Open Ports for Testing

When analyzing scan results, prioritize based on:

1. **Web Services** (80, 443): Often have vulnerabilities and a large attack surface
2. **SMB/Samba** (139, 445): Historically vulnerable to serious exploits
3. **RPC Services** (111, 135): Can provide system information
4. **SSH** (22): Usually less vulnerable but may have version-specific issues

## Security Considerations

- Nmap scans are noticeable and may trigger IDS/IPS alerts
- In real-world scenarios, consider more targeted or slower scans
- Always operate within the scope of your authorization
- Document all scanning activities for client reports
