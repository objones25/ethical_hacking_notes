# Identifying Our Target

## Introduction to Target Identification

Target identification is the critical first step in the reconnaissance phase of ethical hacking. This process involves clearly defining what systems, networks, applications, and organizational assets are within the scope of your security assessment.

## Defining Scope

### Types of Scope Definitions
- **IP Range Based**: Specific IP addresses or CIDR notation blocks
- **Domain Based**: Primary domains and related subdomains
- **Application Based**: Specific web applications or services
- **Cloud Based**: Cloud resources and assets
- **Physical Based**: Physical locations and assets
- **Organizational Based**: Departments or business units

### Common Scope Elements
- Public-facing web applications
- External network infrastructure
- Email systems
- API endpoints
- Mobile applications
- Cloud resources
- Specific functionality or features
- Authentication systems

## Gathering Basic Target Information

### Company and Organization Research
- Legal name and DBA (Doing Business As) names
- Industry and business activities
- Size (employee count, revenue)
- Geographic locations
- Parent companies and subsidiaries
- Recent mergers and acquisitions
- Public vs. private status

### Domain Information
- Primary domain name
- Additional domain names
- Subdomain discovery
- Historical domain information
- Regional domains (.co.uk, .de, etc.)
- Recently acquired domains
- Development and testing domains

### Identifying Technology Stack
- Web servers (Apache, Nginx, IIS)
- Content management systems (WordPress, Drupal)
- Programming languages (PHP, Java, .NET)
- Cloud providers (AWS, Azure, GCP)
- CDN services (Cloudflare, Akamai)
- Database systems (MySQL, Oracle, SQL Server)
- Third-party services and integrations

## Tools for Target Identification

### WHOIS Lookup
- Domain registration information
- Registrar details
- Creation and expiration dates
- Name servers
- Administrative contacts

### DNS Analysis
- **Host Command**:
  ```bash
  host example.com
  ```
- **Dig Command**:
  ```bash
  dig example.com any
  ```
- **NSLookup**:
  ```bash
  nslookup -type=any example.com
  ```

### Web Reconnaissance
- Website exploration and analysis
- Header information examination
- Source code review
- Technology fingerprinting
- Resource analysis (images, documents)
- Error pages and default configurations

### Business Intelligence
- Company websites
- Annual reports
- Press releases
- News articles
- Industry directories
- Social media profiles

## Target Documentation

### Information to Document
- Target name and description
- Primary domain names
- IP address ranges
- Known infrastructure details
- Key technologies identified
- Primary contacts (if applicable)
- Out-of-scope systems or restrictions
- Special considerations or limitations

### Documentation Format
- Clear categorization of information
- Hierarchical organization
- Visual representations where helpful
- Consistent labeling and formatting
- References to information sources
- Date and time of discovery

## Target Validation

### Confirming Ownership
- Verify domain ownership matches expected organization
- Check IP address allocations
- Confirm ASN registrations
- Validate administrative contacts
- Cross-reference business registrations

### Checking Authorization
- Ensure written permission exists
- Verify scope with client point of contact
- Confirm in-scope vs. out-of-scope elements
- Clarify shared hosting considerations
- Validate third-party service testing permissions

## Practical Example: Target Identification Process

### Initial Research Steps
1. Identify primary domain name (example.com)
2. Perform WHOIS lookup on domain
   ```
   $ whois example.com
   ```
3. Check DNS records for additional information
   ```
   $ dig example.com ANY
   ```
4. Visit website and examine visible information
5. View page source for technology clues
6. Check for subdomains and related sites

### Organization Structure Discovery
1. Research corporate structure
2. Identify parent company and subsidiaries
3. Note separate business divisions
4. Map geographical locations
5. Determine key business functions

### Technical Footprint Mapping
1. Identify IP address ranges
2. Discover ASN information
3. Map cloud service usage
4. Identify third-party service providers
5. Document visible security measures

## Example Target Identification Worksheet

### Basic Information
- **Target Name**: Example Corporation
- **Primary Domain**: example.com
- **Additional Domains**: example.net, example-corp.com
- **Industry**: Financial Services
- **Size**: Medium enterprise (1,000-5,000 employees)

### Technical Information
- **IP Ranges**: 203.0.113.0/24, 198.51.100.0/24
- **ASN**: AS12345
- **Hosting Provider**: Example Hosting Inc.
- **Primary Web Server**: Apache/2.4.29
- **CDN Provider**: CloudExample

### Scope Definition
- **In Scope**:
  - example.com and all subdomains
  - 203.0.113.0/24 network range
  - Web applications on primary domain
  - Mobile application (iOS and Android)
  
- **Out of Scope**:
  - Third-party payment processor
  - Customer databases
  - Physical locations
  - Social engineering against employees

## Common Challenges and Solutions

### Challenge: Multiple Business Units
- **Solution**: Clearly document which units are in-scope
- Create separate target profiles for each unit

### Challenge: Cloud Infrastructure
- **Solution**: Identify cloud providers and resources
- Determine ownership boundaries
- Get specific authorization for cloud testing

### Challenge: Shared Hosting
- **Solution**: Verify testing won't impact other customers
- Get explicit permission from hosting provider
- Consider limited-scope testing

### Challenge: Recent Acquisitions
- **Solution**: Research merger/acquisition history
- Identify technological integration status
- Determine whether acquired assets are in-scope

## Resources for Target Identification

### OSINT Tools
- Maltego
- SpiderFoot
- Recon-ng
- Shodan
- Censys

### DNS and Domain Tools
- DNSDumpster
- SecurityTrails
- DomainTools
- ViewDNS.info

### Business Research
- LinkedIn
- Crunchbase
- SEC EDGAR (for public companies)
- D&B Hoovers
- Bloomberg
- Annual reports and 10-K filings
