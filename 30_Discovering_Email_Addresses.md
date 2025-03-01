# Discovering Email Addresses

## Introduction

Email address discovery is a critical component of the reconnaissance phase in ethical hacking. Email addresses can provide valuable insights into an organization's structure, naming conventions, and potential attack vectors. Proper email reconnaissance can support social engineering assessments and help identify potential targets for phishing campaigns or credential testing.

## Email Address Formats and Conventions

### Common Email Formats
- FirstName.LastName@domain.com
- FirstInitial.LastName@domain.com
- FirstName_LastName@domain.com
- LastName.FirstName@domain.com
- FirstInitialLastName@domain.com
- FirstName@domain.com
- FirstName-LastName@domain.com
- FirstInitial_LastName@domain.com

### Departmental Email Addresses
- hr@domain.com
- sales@domain.com
- support@domain.com
- info@domain.com
- admin@domain.com
- it@domain.com
- marketing@domain.com
- security@domain.com

## Email Discovery Techniques

### Website Scraping
- Examining "Contact Us" pages
- Staff directories and team pages
- Press releases and news articles
- Investor relations pages
- Support and feedback forms
- Website source code examination
- Privacy policies and terms of service

### Search Engine Techniques
- Google dorks for finding email addresses:
  ```
  site:domain.com "@domain.com"
  site:domain.com "email" OR "contact" OR "mail"
  site:domain.com filetype:pdf "email"
  ```
- Targeted document searches:
  ```
  site:domain.com filetype:pdf OR filetype:doc OR filetype:xlsx OR filetype:pptx
  ```
- Cached content examination
- Google Groups and mailing list archives

### Social Media Investigation
- LinkedIn profiles and company pages
- Twitter mentions and direct interactions
- Facebook company pages
- GitHub repositories and commits
- Slack community channels
- Forum posts and signatures
- YouTube video descriptions and about pages

### Email Verification Techniques
- SMTP verification (without sending emails)
- Email header analysis
- Checking MX records
- Bounce-back testing
- Email configuration testing

## Tools for Email Discovery

### OSINT Email Discovery Tools
- **theHarvester**: Command-line tool for gathering emails from various sources
  ```
  theHarvester -d domain.com -b google,linkedin
  ```
- **hunter.io**: Web-based email finder using domain search
- **Phonebook.cz**: Simple domain-based email search
- **Clearbit Connect**: Browser extension for finding email addresses
- **EmailHippo**: Email verification service

### GitHub Tools
- **GitGot**: Tool for searching GitHub repositories
- **Gitrob**: Scans GitHub organizations for sensitive files
- **GitHub Dorks**: Search queries for finding emails in repositories

### Custom Tools and Scripts
- Python script for basic email scraping:
  ```python
  import re
  import requests
  
  def get_emails(url):
      response = requests.get(url)
      email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
      return re.findall(email_pattern, response.text)
  ```

### Advanced Email Discovery
- **Maltego**: Visual link analysis with email transforms
- **Recon-ng**: Reconnaissance framework with email modules
- **OSINT Framework**: Collection of OSINT resources
- **SpiderFoot**: Automated OSINT collection platform

## Email Pattern Analysis and Generation

### Identifying Organization Patterns
1. Collect known email addresses from public sources
2. Analyze addresses to identify organizational patterns
3. Generate probable email format for the organization
4. Test with verification tools
5. Create lists of potential addresses based on employee names

### Email Permutation Generators
- **Email-Format**: Shows common email formats for a domain
- **Email Permutator+**: Generate multiple email patterns
- **Linkedin2Username**: Generate usernames from LinkedIn data

### Custom Email Generation Script
```python
def generate_email_permutations(first_name, last_name, domain):
    patterns = [
        f"{first_name}.{last_name}@{domain}",
        f"{first_name[0]}.{last_name}@{domain}",
        f"{first_name}_{last_name}@{domain}",
        f"{last_name}.{first_name}@{domain}",
        f"{first_name[0]}{last_name}@{domain}",
        f"{first_name}@{domain}",
        f"{first_name}-{last_name}@{domain}",
        f"{first_name[0]}_{last_name}@{domain}"
    ]
    return patterns
```

## Data Breach Analysis for Email Discovery

### Leveraging Breach Data
- Search for domain in known breaches
- Analyze leaked email formats
- Cross-reference with employee information
- Identify historical email conventions
- Check for password patterns

### Breach Notification Services
- **HaveIBeenPwned**: Domain search for breached emails
- **DeHashed**: Searchable database of breached records
- **BreachDirectory**: Database of leaked credentials
- **Leak-Lookup**: Service to search for breached data

## Email Verification

### Verification Methods
- **MX Record Check**: Verify domain has valid mail servers
  ```bash
  dig MX domain.com
  ```
- **SMTP Verification**: Check if email exists without sending mail
  ```python
  import smtplib
  
  def verify_email(email):
      domain = email.split('@')[1]
      mx_records = get_mx_records(domain)
      if not mx_records:
          return "Invalid domain MX records"
      
      server = smtplib.SMTP(mx_records[0])
      server.helo('test.com')
      server.mail('test@test.com')
      code, message = server.rcpt(email)
      server.quit()
      
      if code == 250:
          return "Valid"
      else:
          return "Invalid"
  ```
- **API Services**: Various email verification APIs

### Verification Tools
- **Email Hippo**: Verification without sending emails
- **NeverBounce**: Email verification and list cleaning
- **Verify-Email.org**: Simple email verification
- **Email-Checker.net**: Free basic email verification

## Documentation and Organization

### Information to Record
- Email address discovered
- Source of discovery
- Date found
- Associated information (name, title, department)
- Verification status
- Breach history
- Pattern analysis

### Organization Methods
- Spreadsheet tracking
- Mind mapping tools
- Visual relationship graphs
- Database storage with search capability
- Tagging for role and department

## Legal and Ethical Considerations

### Legal Boundaries
- Only collect publicly available information
- Adhere to terms of service for websites and tools
- Don't use aggressive scraping techniques
- Stay within authorized scope of work
- Be aware of privacy laws like GDPR

### Ethical Guidelines
- Don't use discovered emails for spam
- Secure any collected information properly
- Only use information for authorized testing
- Report critical findings according to proper channels
- Delete information when project is complete

## Leveraging Email Discoveries

### Security Testing Applications
- Targeted phishing simulation campaigns
- Password spray and credential testing
- Social engineering assessments
- Username enumeration
- Access control testing

### Reporting Recommendations
- Email security policy improvements
- Employee awareness training suggestions
- Public exposure reduction strategies
- Data leak monitoring recommendations
- Email filtering and protection measures

## Example Email Discovery Workflow

1. Identify target domain
2. Perform basic web searches for email formats
3. Use specialized tools (theHarvester, hunter.io)
4. Check social media and professional networks
5. Analyze results to identify email patterns
6. Generate potential emails using discovered patterns
7. Verify email existence
8. Document findings and patterns
9. Test security awareness using discovered emails (if authorized)
10. Provide recommendations for reducing email exposure

## Common Challenges and Solutions

### Challenge: Email Protection Services
- **Solution**: Focus on historical data and cached content
- Target subsidiary domains that might be less protected

### Challenge: Limited Public Information
- **Solution**: Expand search to partners, suppliers, and customers
- Look for external presentations and conference materials

### Challenge: Multiple Email Formats
- **Solution**: Document all discovered formats
- Group emails by department or acquisition history
- Test all potential formats

### Challenge: Email Verification Blocks
- **Solution**: Use passive verification techniques
- Space out verification attempts
- Leverage breach data for confirmation
