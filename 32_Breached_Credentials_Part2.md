# Breached Credentials - Part 2

## Leveraging Breached Credentials in Ethical Hacking

### Authorized Use Cases
- Password policy assessment
- User awareness evaluation
- Credential stuffing simulation
- Password reuse detection
- Authentication security testing
- Multi-factor authentication bypass assessment
- Security awareness training

### Testing Methodologies
- Password spraying (controlled)
- Targeted credential testing
- External service testing (approved)
- Password reset function assessment
- Account lockout testing
- MFA implementation testing
- SSO security evaluation

## Password Analysis and Cracking

### Understanding Password Hashing
- **Hash Functions**: One-way mathematical functions that convert passwords to fixed-length strings
- **Common Hash Types**:
  - MD5 (obsolete, fast)
  - SHA-1 (deprecated, relatively fast)
  - SHA-256/SHA-512 (stronger, moderate speed)
  - bcrypt (slow by design, includes salt)
  - Argon2 (modern, memory-hard function)
  - PBKDF2 (iterative, configurable)
- **Salting**: Adding random data to passwords before hashing to prevent rainbow table attacks

### Password Cracking Techniques
- **Dictionary Attacks**: Using wordlists of common passwords
  ```bash
  hashcat -m 0 -a 0 hashes.txt wordlist.txt
  ```
- **Rule-Based Attacks**: Applying transformation rules to wordlists
  ```bash
  hashcat -m 0 -a 0 hashes.txt wordlist.txt -r rules/best64.rule
  ```
- **Brute Force**: Trying all possible character combinations
  ```bash
  hashcat -m 0 -a 3 hashes.txt ?a?a?a?a?a?a
  ```
- **Hybrid Attacks**: Combining dictionary words with pattern masks
  ```bash
  hashcat -m 0 -a 6 hashes.txt wordlist.txt ?d?d?d?d
  ```
- **Rainbow Tables**: Precomputed hash tables for faster lookups
- **Markov Chain Attacks**: Statistical models based on character probabilities

### Password Cracking Tools
- **Hashcat**: GPU-accelerated password recovery tool
- **John the Ripper**: Versatile password cracker
- **Hydra**: Online password brute forcing tool
- **Medusa**: Parallel password brute forcer
- **Aircrack-ng**: Wireless password cracking suite

### Creating Custom Wordlists
- **Company-Specific**: Based on company information and jargon
- **Target-Specific**: Based on personal information from social media
- **Industry-Specific**: Based on industry terminology and patterns
- **CeWL**: Generate wordlists from company websites
  ```bash
  cewl -d 2 -m 5 https://example.com -w wordlist.txt
  ```
- **Wordlist Manipulation Tools**:
  ```bash
  # Combine wordlists
  cat wordlist1.txt wordlist2.txt > combined.txt
  
  # Remove duplicates
  sort combined.txt | uniq > deduplicated.txt
  ```

## Credential Testing and Verification

### Credential Stuffing
- **Definition**: Automated testing of breached username/password pairs against multiple services
- **Methodology**:
  1. Obtain credential pairs from breaches
  2. Create lists of services to test
  3. Automate login attempts (with authorization)
  4. Document successful authentications
  5. Analyze patterns in successful logins

### Password Spraying
- **Definition**: Testing a small set of common passwords against many accounts
- **Methodology**:
  1. Identify valid usernames/email addresses
  2. Select common passwords based on analysis
  3. Attempt logins with controlled timing
  4. Monitor for lockouts and alerts
  5. Document successful authentications

### Testing Tools
- **Burp Suite Intruder**: For web application testing
- **Patator**: Multi-purpose brute-forcer
  ```bash
  patator http_fuzz url=https://example.com/login method=POST body='user=FILE0&password=FILE1' 0=users.txt 1=passwords.txt -x ignore:fgrep='Login failed'
  ```
- **Hydra**: Network login cracker
  ```bash
  hydra -L users.txt -P passwords.txt example.com http-post-form "/login:username=^USER^&password=^PASS^:F=Login failed"
  ```
- **Metasploit Auxiliary Modules**: Various login/brute force modules
  ```
  use auxiliary/scanner/http/http_login
  set RHOSTS example.com
  set USER_FILE users.txt
  set PASS_FILE passwords.txt
  set STOP_ON_SUCCESS true
  run
  ```

### Risk Mitigation During Testing
- Use throttled testing to avoid lockouts
- Coordinate with security teams before testing
- Monitor for abnormal system behavior
- Have rollback plans for any issues
- Test during low-traffic periods
- Use dedicated testing accounts when possible

## Implementing Defensive Measures

### Technical Controls
- **Password Policies**:
  - Minimum length requirements (12+ characters)
  - Complexity requirements
  - Prohibit common passwords
  - Ban password reuse
  - Regular password changes (with caution)
  
- **Authentication Enhancements**:
  - Multi-factor authentication (MFA)
  - Passwordless authentication options
  - Risk-based authentication
  - CAPTCHA for repeated attempts
  - Biometric authentication options
  
- **Monitoring and Detection**:
  - Login attempt rate limiting
  - Geographic-based access controls
  - Behavior-based anomaly detection
  - Failed login attempt monitoring
  - Session analysis and monitoring

### Organizational Controls
- **User Training**:
  - Password manager usage
  - Recognizing phishing attempts
  - Safe password practices
  - Breach awareness
  - Reporting suspicious activity
  
- **Incident Response**:
  - Breach notification procedures
  - Password reset workflows
  - Compromised account recovery
  - Forensic investigation protocols
  - Communication templates and plans

### Preventative Measures
- Regular credential auditing
- Breach notification monitoring
- Third-party service assessment
- Password manager deployment
- Dark web monitoring for leaked credentials
- Internal phishing simulations
- Regular security awareness training

## Advanced Credential Analysis

### Analyzing Password Reset and Recovery
- Password reset mechanisms
- Security questions and answers
- Email recovery security
- SMS recovery vulnerabilities
- Account recovery timelines
- Session handling after password changes

### Cross-Account Analysis
- Identifying password reuse across services
- Detecting shared password patterns
- Analyzing credential reuse across corporate/personal accounts
- Identifying shared recovery emails and phones
- Detecting synchronized password changes

### Temporal Analysis
- Password aging and change patterns
- Time-based patterns in passwords (seasons, years)
- Password changes following breaches
- Password lifecycle analysis
- Correlation with security events

## Case Studies and Examples

### Example 1: Corporate Password Pattern Analysis
- Analysis of breached corporate passwords revealed 67% followed the pattern:
  - Company name + 2-4 digits (often year or month)
  - Example: "CompanyName2023"
- 34% of these were reused across multiple services
- Recommendation: Implement a password manager and MFA

### Example 2: Password Spraying Success Rates
- Testing 10 common passwords against 1,000 accounts:
  - Success rate: 3.7% (37 compromised accounts)
  - Top successful password: "Winter2023!"
  - 12 accounts had passwords matching company + year pattern
- Recommendation: Implement password strength requirements and banned password lists

### Example 3: Cross-Service Credential Reuse
- 42% of corporate email addresses found in public breaches
- 23% of tested accounts had identical passwords on corporate and personal accounts
- 8% of tested accounts had slight variations (Company123 vs Company456)
- Recommendation: Security awareness training and external breach monitoring

## Reporting and Remediation

### Reporting Elements
- Executive summary with key findings
- Credential exposure statistics
- Password pattern analysis
- Technical details and evidence
- Risk assessment and potential impact
- Comparison to industry benchmarks
- Detailed recommendations

### Remediation Steps
1. **Immediate Actions**:
   - Force reset of compromised passwords
   - Implement account monitoring
   - Review authentication logs
   - Enable MFA for critical accounts

2. **Short-term Actions**:
   - Deploy password manager
   - Update password policies
   - Implement breach monitoring
   - Conduct targeted security training

3. **Long-term Actions**:
   - Consider passwordless authentication
   - Implement ongoing credential monitoring
   - Regular credential security assessments
   - Develop comprehensive identity strategy

### Post-Remediation Verification
- Follow-up testing to verify fixes
- Ongoing monitoring for new exposures
- Periodic reassessment of credential security
- Measurement of security awareness improvements
- Testing of new authentication methods

## Resources and Tools

### Common Password Lists
- RockYou.txt (14 million passwords)
- Have I Been Pwned password list
- SecLists password collection
- Daniel Miessler's password lists
- Weakpass wordlists

### Breach Monitoring Resources
- Have I Been Pwned API and notification service
- Firefox Monitor
- Breach notification services
- Dark web monitoring services
- Security researcher breach notifications

### Learning Resources
- OWASP Authentication Guidelines
- NIST Digital Identity Guidelines (SP 800-63B)
- Troy Hunt's blog on password security
- The Password Game by Dropbox
- "Practical Password Security" (various authors)

## Conclusion

Analyzing breached credentials provides valuable insights into an organization's password security, user behavior, and potential vulnerabilities. By ethically leveraging this information within legal boundaries and with proper authorization, security professionals can:

1. Identify and address existing vulnerabilities
2. Develop targeted security improvements
3. Enhance user awareness and training
4. Implement more effective authentication controls
5. Reduce the risk of credential-based attacks

The key to success is conducting this analysis ethically, securing any breached data properly, and using the information solely for improving security posture rather than exploitation.
