# Credential Stuffing & Password Spraying

## Introduction

Credential stuffing and password spraying are two popular authentication attack techniques that exploit weak password practices. While they share similarities, they use different approaches to achieve their goals. This document explains both techniques, their differences, use cases, tools, and countermeasures.

## Credential Stuffing

### Definition

Credential stuffing is an attack where attackers use previously leaked username/password combinations (from data breaches) to attempt to gain unauthorized access to user accounts on different services.

### How Credential Stuffing Works

1. **Data Collection**: Attackers obtain leaked credentials from data breaches, dark web markets, or paste sites
2. **Preparation**: Credentials are formatted and organized for automated testing
3. **Automation**: Bots or scripts attempt to log in to various services using these credentials
4. **Exploitation**: Successfully authenticated accounts are flagged for further actions

### Why Credential Stuffing Is Effective

- **Password Reuse**: Many users reuse the same password across multiple services
- **Breach Volume**: Billions of credentials have been exposed in previous data breaches
- **Automation**: Modern tools make testing millions of credentials feasible
- **Success Rate**: Even a low success rate (usually 0.1-2%) yields many compromised accounts

### Examples of Credential Stuffing Attacks

- **2018 Reddit Breach**: Attackers used credential stuffing to access employee accounts
- **2020 Zoom Credential Stuffing**: Over 500,000 Zoom accounts were compromised
- **2019 Disney+ Launch**: Thousands of accounts were hijacked shortly after launch

## Password Spraying

### Definition

Password spraying is an attack where attackers attempt to access a large number of accounts using a small set of commonly used passwords, trying each password against multiple accounts before moving to the next password.

### How Password Spraying Works

1. **Username Enumeration**: Collect valid usernames (often from email directories, social media, etc.)
2. **Password Selection**: Select a small list of common passwords or organization-specific passwords
3. **Controlled Attempts**: Try a single password against many accounts before moving to the next password
4. **Timing Control**: Space out attempts to avoid triggering account lockouts

### Why Password Spraying Is Effective

- **Common Passwords**: Many users still use predictable passwords (e.g., "Password123", "Spring2023!")
- **Lockout Bypass**: Avoids account lockout by limiting attempts per account
- **Organizational Patterns**: Many organizations have predictable password patterns
- **Default Credentials**: New accounts often start with predictable passwords

### Examples of Password Spraying Attacks

- **2019 Citrix Breach**: Attackers used password spraying to access internal networks
- **2018 British Airways**: Password spraying contributed to the compromise of customer data
- **Multiple Government Agencies**: APT groups frequently use password spraying as an initial access technique

## Key Differences Between the Techniques

| Aspect | Credential Stuffing | Password Spraying |
|--------|---------------------|-------------------|
| **Input Data** | Known username/password pairs | List of valid usernames + few common passwords |
| **Attempt Pattern** | Many passwords per user | Few passwords across many users |
| **Required Knowledge** | Leaked credentials | Only valid usernames |
| **Detection Triggering** | Account lockouts more likely | Designed to avoid lockout policies |
| **Success Rate** | Higher per attempt (if passwords are reused) | Lower per attempt but evades controls |
| **Primary Target** | Consumer services | Enterprise environments |

## Tools for Credential Stuffing and Password Spraying

### Credential Stuffing Tools

1. **Sentry MBA**: Configurable framework with CAPTCHA bypass capabilities
   ```
   # Note: For educational purposes only - actual usage varies
   sentry_mba.exe -config amazon.txt -combolist leaked_creds.txt
   ```

2. **SNIPR**: Specialized tool for credential stuffing attacks
   ```
   # Note: For educational purposes only
   snipr.exe -config site.xml -list combo.txt -threads 10
   ```

3. **Hydra**: Multi-protocol password cracker
   ```
   hydra -C leaked_combo.txt service://target
   ```

4. **Custom Scripts**: Python/Ruby scripts using requests libraries
   ```python
   import requests
   
   with open('combo.txt') as f:
       for line in f:
           username, password = line.strip().split(':')
           r = requests.post('https://example.com/login', 
                            data={'user': username, 'pass': password})
           if "success" in r.text:
               print(f"Valid: {username}:{password}")
   ```

### Password Spraying Tools

1. **Spray**: PowerShell-based password spraying tool
   ```powershell
   Invoke-SpraySinglePassword -Password 'Spring2023!' -UserList users.txt -Url https://example.com/login
   ```

2. **MailSniper**: Exchange/OWA password spraying
   ```powershell
   Invoke-PasswordSprayOWA -ExchHostname mail.company.com -UserList users.txt -Password 'Winter2023!'
   ```

3. **Metasploit Auxiliary Modules**:
   ```
   use auxiliary/scanner/http/http_login
   set USERPASS_FILE combo.txt
   set RHOSTS target.com
   run
   ```

4. **SprayingToolkit**: Multiple services (Office 365, OWA, Lync/Skype)
   ```
   python3 sprayingtoolkit.py -u usernames.txt -p passwords.txt -t o365
   ```

## Attack Methodology

### Credential Stuffing Approach

1. **Acquire Breach Data**: Obtain leaked credentials from breaches
2. **Format and Clean**: Prepare credential lists in correct format
3. **Select Target Service**: Choose which service(s) to attack
4. **Configure Tools**: Set up automation with proper request formatting
5. **Execute Attack**: Run credential testing across target services
6. **Handle Results**: Process successful logins for further action

### Password Spraying Approach

1. **Gather Usernames**: Collect valid usernames for the target
2. **Research Password Patterns**: Identify common passwords for the organization
3. **Plan Attack Timeline**: Schedule attempts to avoid lockouts (e.g., 1 password per 30 minutes)
4. **Prepare Password List**: Select high-probability passwords
5. **Execute Controlled Spraying**: Try each password against all accounts
6. **Document Successes**: Record successful authentications

## Detection and Prevention

### Detecting Credential Stuffing

1. **Volumetric Analysis**: Monitor for high volumes of login attempts
2. **IP Reputation**: Track login attempts from known malicious IPs
3. **Impossible Travel**: Alert on logins from geographically impossible locations
4. **User Agent Inconsistency**: Watch for unusual browser/client signatures
5. **Failed Login Patterns**: Identify automated patterns in failed attempts

### Detecting Password Spraying

1. **Authentication Timing**: Monitor for synchronized login attempts
2. **Account-Password Ratios**: Track password-to-account attempt ratios
3. **Horizontal Login Monitoring**: Detect same password used across multiple accounts
4. **Baseline Deviation**: Alert on abnormal authentication patterns
5. **Time-of-Day Analysis**: Watch for attempts outside normal business hours

### Mitigation Strategies

1. **Multi-Factor Authentication (MFA)**: Implement across all services
2. **CAPTCHA/reCAPTCHA**: Challenge suspicious login attempts
3. **Progressive Delays**: Increase wait time between failed attempts
4. **IP-based Rate Limiting**: Limit login attempts from a single source
5. **Credential Breach Monitoring**: Check new passwords against known breached credentials
6. **Password Policy Enforcement**: Require strong, unique passwords
7. **Risk-Based Authentication**: Apply additional verification for suspicious logins
8. **User Education**: Train users about password reuse risks

## Legal and Ethical Considerations

- **Authorization**: Only conduct these attacks with explicit permission
- **Rules of Engagement**: Define and document the scope and limitations
- **Data Handling**: Properly secure and dispose of credential data
- **Privacy Considerations**: Respect user privacy during testing
- **Reporting Process**: Document findings and recommendations professionally

## Conclusion

Credential stuffing and password spraying remain highly effective attack techniques due to continued poor password practices. Understanding these attacks helps security professionals implement appropriate countermeasures and detection strategies. For ethical hackers, these techniques provide valuable testing methods that simulate real-world threats, though they must be used responsibly and only with proper authorization.

Both attacks exploit the human element of security systems, underlining the importance of comprehensive security awareness training alongside technical controls. By implementing a layered approach to authentication security, organizations can significantly reduce their vulnerability to these common attack techniques.
