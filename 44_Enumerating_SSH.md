# Enumerating SSH

## Introduction to SSH Enumeration

Secure Shell (SSH) is a cryptographic network protocol used for secure remote login and other secure network services. While SSH is designed to be secure, proper enumeration can reveal valuable information and potential vulnerabilities.

## Initial SSH Service Identification

The Nmap scan previously identified SSH running on port 22:
```
22/tcp open ssh OpenSSH 2.9p2 (Protocol 1.99)
```

This already provides valuable information:
- The service is OpenSSH
- The version is 2.9p2
- It supports Protocol 1.99 (compatibility mode for both SSH1 and SSH2)

## Basic SSH Banner Grabbing

### Manual Banner Grabbing with Telnet
```bash
telnet 192.168.1.10 22
```

Example output:
```
SSH-1.99-OpenSSH_2.9p2
```

### Using Netcat for Banner Grabbing
```bash
nc 192.168.1.10 22
```

### Attempting SSH Connection
Connecting with the SSH client also reveals banner information:
```bash
ssh 192.168.1.10
```

## SSH Version Analysis

The version information is critical for identifying potential vulnerabilities:

- OpenSSH 2.9p2 is extremely outdated (released around 2002)
- SSH Protocol 1 has known security issues
- Search for CVEs (Common Vulnerabilities and Exposures) related to this version
- Older versions may have issues with:
  - Authentication bypass
  - Information disclosure
  - Cryptographic weaknesses
  - Denial of service vulnerabilities

## SSH Configuration Enumeration

### Identifying Supported Authentication Methods
```bash
ssh -v 192.168.1.10
```

Look for lines like:
```
debug1: Authentications that can continue: publickey,password,keyboard-interactive
```

This shows which authentication methods are enabled, which can inform your attack strategy:
- Password authentication allows for brute force attacks
- Keyboard-interactive may be vulnerable to automated attacks
- Public key authentication is generally more secure

### Testing for Key Exchange Algorithms
```bash
ssh -vv 192.168.1.10
```

The verbose output will show supported key exchange methods, ciphers, and MAC algorithms, which may reveal weak cryptographic configurations.

## User Enumeration via SSH

Some SSH configurations leak valid usernames:

```bash
ssh nonexistentuser@192.168.1.10
ssh existinguser@192.168.1.10
```

Compare the responses. Different error messages may indicate whether a username exists:
- "Access denied for user" vs. "No such user exists"
- Timing differences in responses

## SSH Brute Force Considerations

While brute forcing is typically a later stage activity, for educational purposes:

### Using Hydra for SSH Brute Force
```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt 192.168.1.10 ssh
```

### Metasploit SSH Login Scanner
```
use auxiliary/scanner/ssh/ssh_login
set RHOSTS 192.168.1.10
set USER_FILE /path/to/users.txt
set PASS_FILE /path/to/passwords.txt
run
```

## SSH Security Best Practices

For report recommendations, consider noting these best practices:
- Disable SSH Protocol 1
- Update to the latest SSH version
- Implement key-based authentication
- Disable root login
- Use strong password policies
- Implement login attempt rate limiting
- Consider port knocking or changing the default port

## Documenting SSH Findings

Comprehensive documentation should include:

```
Service: SSH (Port 22)
Version: OpenSSH 2.9p2 (Protocol 1.99)
Banner: SSH-1.99-OpenSSH_2.9p2
Authentication Methods: [methods identified]
User Enumeration Possible: Yes/No
Known Vulnerabilities: [list CVEs]
Brute Force Protection: Present/Absent
```

## SSH Enumeration Summary

SSH enumeration focuses on:
1. Identifying the exact version and protocol
2. Determining supported authentication methods
3. Testing for information disclosure like username enumeration
4. Analyzing security configurations
5. Researching known vulnerabilities for the specific version

Unlike web services or SMB, SSH typically requires valid credentials for further exploitation, making initial enumeration and credential discovery critical steps.
