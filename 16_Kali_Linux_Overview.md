# Kali Linux Overview (2:01:17)

## What is Kali Linux?
- Linux distribution specifically designed for penetration testing and digital forensics
- Based on Debian Linux
- Developed and maintained by Offensive Security
- Comes pre-loaded with hundreds of security and penetration testing tools
- Industry standard for ethical hacking and security assessments

## Key Features
1. **Pre-installed Security Tools**
   - Network scanning (Nmap, Wireshark)
   - Vulnerability assessment (OpenVAS, Nikto)
   - Password cracking (John the Ripper, Hashcat)
   - Web application testing (Burp Suite, OWASP ZAP)
   - Exploitation frameworks (Metasploit)
   - Wireless testing tools (Aircrack-ng)
   - Forensics tools

2. **System Structure**
   - Default desktop environment: Xfce (lightweight and efficient)
   - Highly customizable interface
   - Root user is the default (differs from most Linux distributions)

3. **Package Management**
   - Uses APT (Advanced Package Tool) for managing software
   - Regular updates from Kali repositories
   - Simple installation of additional tools

## Default Applications
- **Web Browsers**: Firefox
- **Terminal Emulator**: GNOME Terminal
- **Text Editors**: Leafpad, Vim, Nano
- **File Manager**: Thunar

## Desktop Environment
- Applications menu (categories for different tools)
- Terminal-centric workflow
- Quick access to common tools
- Multiple workspaces for organization

## Tool Categories
1. **Information Gathering**
   - Network reconnaissance
   - OSINT (Open Source Intelligence)
   - DNS analysis

2. **Vulnerability Assessment**
   - Scanning for vulnerabilities
   - Service enumeration
   - Compliance testing

3. **Web Application Analysis**
   - Website scanning
   - CMS identification
   - SQL injection testing

4. **Database Assessment**
   - Database enumeration
   - Exploitation tools

5. **Password Attacks**
   - Brute force tools
   - Dictionary attacks
   - Hash cracking

6. **Wireless Attacks**
   - WiFi security assessment
   - Bluetooth testing

7. **Exploitation Tools**
   - Frameworks like Metasploit
   - Reverse engineering tools

8. **Sniffing & Spoofing**
   - Network traffic analysis
   - Man-in-the-middle tools

9. **Post Exploitation**
   - Privilege escalation
   - Maintaining access
   - Data exfiltration

10. **Forensics**
    - Disk analysis
    - Memory forensics
    - File recovery

11. **Reporting Tools**
    - Documentation
    - Evidence collection

## Best Practices
- Update regularly: `apt update && apt upgrade`
- Create snapshots before major changes
- Use as part of a security testing methodology
- Document all activities and findings
