# Breached Credentials - Part 1

## Introduction to Breached Credentials

Breached credentials are usernames, email addresses, and passwords that have been exposed through data breaches. These breaches occur when unauthorized individuals gain access to databases containing user information. For ethical hackers, analyzing breached credentials provides valuable insights into password patterns, user behavior, and potential security vulnerabilities within an organization.

## The Scale and Impact of Data Breaches

### Major Data Breaches
- Yahoo (2013-2014): 3 billion user accounts
- LinkedIn (2012/2016): 165 million accounts
- Adobe (2013): 153 million accounts
- eBay (2014): 145 million users
- Equifax (2017): 147 million users
- Marriott (2018): 500 million customers
- Facebook (2019): 533 million users
- Collection #1 (2019): 87 GB of breached data from multiple sources

### Impact on Organizations
- Reputation damage
- Financial losses
- Regulatory fines
- Legal actions
- Decreased customer trust
- Operational disruption
- Intellectual property theft
- Costs of breach remediation

### Impact on Users
- Identity theft
- Financial fraud
- Account takeovers
- Spear phishing targets
- Credential stuffing attacks
- Privacy violations
- Personal and professional reputation damage

## Types of Breached Data

### Credential Information
- Email addresses
- Usernames
- Passwords (hashed or plaintext)
- Password hints
- Security questions and answers

### Personal Information
- Full names
- Phone numbers
- Physical addresses
- Date of birth
- Social Security Numbers/National IDs
- Payment information
- IP addresses
- Device information

### Account Information
- Account creation dates
- Last login timestamps
- Account status
- Role/permissions
- Subscription details
- Purchase history

## How Credentials Get Breached

### Technical Vulnerabilities
- SQL injection
- Unpatched systems
- Insecure APIs
- Default or weak credentials
- Improper access controls
- Misconfigured databases
- Insecure storage of credentials

### Social Engineering
- Phishing campaigns
- Business email compromise
- Pretexting
- Baiting
- Impersonation

### Insider Threats
- Malicious employees
- Accidental data exposure
- Third-party vendor compromises
- Contractor access abuse

### Poor Security Practices
- Lack of encryption
- Inadequate monitoring
- Insufficient logging
- Weak authentication requirements
- Improper secret management
- Password reuse across systems

## Legal and Ethical Considerations

### Legal Aspects
- Unauthorized access to breached data may violate laws
- Possession of certain breached data may be illegal
- Proper authorization is required before testing credentials
- Data privacy regulations (GDPR, CCPA) govern use of personal data
- Different jurisdictions have varying laws on data breaches

### Ethical Guidelines
- Only use breached data for legitimate security testing
- Obtain proper authorization before testing credentials
- Do not share or distribute breached data
- Secure any breached data in your possession
- Delete data when it is no longer needed
- Report previously unknown breaches to affected organizations
- Follow responsible disclosure practices

## Sources of Breached Credentials

### Public Breach Notification Services
- **Have I Been Pwned (HIBP)**: Database of breached email accounts
- **Firefox Monitor**: Service powered by HIBP data
- **BreachAlarm**: Email monitoring for breaches
- **Google Password Checkup**: Chrome extension to check for compromised passwords

### Commercial Services
- **DeHashed**: Searchable database of breached records (paid)
- **Spycloud**: Breach monitoring and alerting (commercial)
- **BreachDirectory**: Database of leaked credentials
- **IntelligenceX**: Search engine for leaked data (commercial)

### Underground Markets and Forums
- Dark web marketplaces
- Hacking forums
- Telegram channels
- IRC channels
- Paste sites (Pastebin, etc.)

### Open Source Intelligence (OSINT)
- GitHub repositories
- Public cloud storage
- Search engine cached data
- Public datasets
- Academic research datasets

## Tools for Finding and Analyzing Breached Credentials

### Search Tools
- **H8mail**: Email OSINT tool and breach hunter
  ```bash
  h8mail -t target@example.com
  ```
- **Breach-Parse**: Tool for parsing breach data
- **Holehe**: Check if email is registered on different sites
  ```bash
  holehe example@domain.com
  ```
- **Scylla**: Breach data search engine (self-hosted)

### APIs and Services
- **Have I Been Pwned API**: Check emails against known breaches
- **Pwned Passwords API**: Check password hashes without revealing passwords
  ```
  GET https://api.pwnedpasswords.com/range/5BAA6
  ```
- **DeHashed API**: Commercial API for breach data

### Password Analysis Tools
- **HashCat**: Password recovery utility
  ```bash
  hashcat -m 0 -a 0 hash.txt wordlist.txt
  ```
- **John the Ripper**: Password cracking tool
  ```bash
  john --format=raw-md5 hash.txt
  ```
- **CeWL**: Custom wordlist generator
  ```bash
  cewl -d 2 -m 5 https://example.com -w wordlist.txt
  ```

## Finding Breached Credentials for an Organization

### Domain-Based Searches
- Search for email addresses with the organization's domain
- Look for corporate email patterns (@company.com)
- Check subdomains and alternative domains
- Search for company name in breach descriptions

### Employee-Based Searches
- Search for known employee email addresses
- Look for pattern matches based on employee naming conventions
- Cross-reference with professional profiles (LinkedIn, etc.)
- Search for company-specific usernames or IDs

### Technical Indicators
- Search for internal IP addresses
- Look for internal hostnames
- Check for company-specific email signatures
- Search for company-specific terminology or jargon

### Search Methodology
1. Identify all company domains and email formats
2. Gather known employee names and email addresses
3. Check breach notification services for domain presence
4. Search commercial and public databases for specific details
5. Create a list of potentially affected accounts
6. Analyze patterns in breached credentials
7. Document findings and sources

## Analyzing Password Patterns

### Common Password Patterns
- Company name + numbers (Company123)
- Seasonal patterns (Summer2023!)
- Keyboard patterns (Qwerty123)
- Common substitutions (P@ssw0rd)
- Name/birth date combinations
- Sports teams and mascots
- Common words with predictable modifications

### Organization-Specific Patterns
- Company name variations
- Project names or product codes
- Office locations
- Company slogans or mottos
- Founding year or significant dates
- Internal terminology

### Analysis Techniques
- Identify password length distributions
- Detect character type usage patterns
- Find common words and variations
- Analyze number placement and patterns
- Look for compliance with password policies
- Identify patterns suggesting password reuse

## Documentation and Reporting

### What to Document
- Sources of breached credentials
- Number of affected accounts
- Types of exposed information
- Password patterns identified
- Evidence of password reuse
- Timeframe of breaches
- Systems potentially affected

### Reporting Elements
- Executive summary of findings
- Scope and methodology
- Detailed findings with evidence
- Risk assessment
- Pattern analysis
- Recommendations for remediation
- References and appendices
