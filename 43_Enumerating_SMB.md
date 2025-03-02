# Enumerating SMB

## Introduction to SMB Enumeration

Server Message Block (SMB) is a protocol used for sharing files, printers, and other resources on a network. It's commonly found in corporate environments and is a high-value target for penetration testers.

## Why SMB is Important for Penetration Testing

- Commonly found in Windows environments and some Linux servers (Samba)
- Historically vulnerable to numerous exploits (EternalBlue/MS17-010)
- Often contains sensitive files and information
- May allow anonymous access or have weak authentication
- Can reveal system information, usernames, and network details

## Using Metasploit for SMB Enumeration

### Starting Metasploit
```bash
msfconsole
```

### Finding SMB Version Information
```
msf6 > search smb
msf6 > use auxiliary/scanner/smb/smb_version
msf6 > options
msf6 > set RHOSTS 192.168.1.10
msf6 > run
```

Sample output:
```
[+] 192.168.1.10:139     - Host is running Samba 2.2.1a (Linux)
```

### Understanding Metasploit Auxiliary Modules
- **Auxiliary modules**: Used for scanning, enumeration, and information gathering
- **Scanner modules**: Designed to scan multiple hosts for specific services or vulnerabilities
- **SMB modules**: Target SMB protocol for various enumeration and exploitation tasks

### Additional Useful SMB Enumeration Modules
```
auxiliary/scanner/smb/smb_enumshares
auxiliary/scanner/smb/smb_enumusers
auxiliary/scanner/smb/smb_lookupsid
auxiliary/scanner/smb/pipe_auditor
```

## Using SMBclient for Share Enumeration

SMBclient is a command-line utility similar to an FTP client for accessing SMB resources.

### Listing Available Shares
```bash
smbclient -L //192.168.1.10/
```
Enter a blank password when prompted (for anonymous access attempts).

Example output:
```
Sharename      Type      Comment
---------      ----      -------
IPC$           IPC       IPC Service (Samba Server)
ADMIN$         Disk      IPC Service (Samba Server)
```

### Connecting to a Share
```bash
smbclient //192.168.1.10/ADMIN$ 
```
Enter password when prompted or try anonymous access.

### Navigating Once Connected
If successfully connected, you can use commands similar to FTP:
```
smb: \> ls
smb: \> cd directory
smb: \> get filename
smb: \> put filename
smb: \> exit
```

## SMB Connection Outcomes

### Anonymous Access Denied
If you see "NT_STATUS_ACCESS_DENIED", this means:
- Anonymous access is not allowed
- You need valid credentials to access the share
- May need to try brute forcing or find credentials elsewhere

### Anonymous Access Successful
If you successfully connect but see "Access Denied" for commands:
- You have connected to the share but have limited permissions
- Document this finding as it's still a security issue
- Try navigating to different directories to find accessible areas

### Full Anonymous Access
If you can list and access files:
- This is a significant security issue
- Download and examine accessible files
- Look for configuration files, credentials, and sensitive data
- Check file permissions to see if you can upload files

## Additional SMB Enumeration Tools

### enum4linux
A tool for enumerating information from Windows and Samba systems.
```bash
enum4linux -a 192.168.1.10
```
This performs all enumeration options including:
- User listing
- Share listing
- Group and member listing
- Password policy information
- OS information
- RID cycling (to enumerate users)

### rpcclient
Low-level command-line tool for accessing MS-RPC functionality.
```bash
rpcclient -U "" -N 192.168.1.10
```
If successful:
```
rpcclient $> srvinfo
rpcclient $> enumdomusers
rpcclient $> queryuser username
```

## Common SMB Findings and Next Steps

### Outdated SMB Versions
- Samba 2.2.x is very outdated and likely vulnerable
- Document the exact version for vulnerability research
- Check for known exploits in Metasploit or ExploitDB

### Anonymous Access to Shares
- Anonymous access to non-public shares is a security issue
- Check accessible files for sensitive information
- Test if you can upload files to the shares

### User Enumeration
- If you can enumerate users, document for password attacks
- Look for default or service accounts
- Consider password spraying with common passwords

## Documenting SMB Enumeration Results

Create comprehensive notes for each discovery:
```
Service: SMB (139/445)
Version: Samba 2.2.1a (Linux)
Shares Found: IPC$, ADMIN$
Anonymous Access: Yes/No/Partial
Users Enumerated: [list if found]
Potential Vulnerabilities: [based on version]
```
