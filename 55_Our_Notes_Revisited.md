# Our Notes, Revisited

## Introduction

As we progress through our ethical hacking journey, it's valuable to revisit our notes and refine our documentation approach. Good notes are not only useful during the current engagement but also serve as a reference for future assessments and report writing. This document explores advanced note-taking strategies, tools, and organization methods.

## The Evolution of Penetration Testing Notes

### From Basic to Comprehensive

1. **Initial Approach**: Simple text files with commands and outputs
2. **Intermediate**: Structured documentation with categories and findings
3. **Advanced**: Integrated documentation systems with evidence, screenshots, and linked references

### The Purpose of Revisiting Notes

1. **Consolidation**: Combine scattered information into a cohesive narrative
2. **Pattern Recognition**: Identify recurring vulnerabilities or attack paths
3. **Knowledge Gaps**: Identify areas requiring further research or testing
4. **Report Preparation**: Organize findings for effective reporting

## Advanced Note-Taking Systems

### Hierarchical Documentation

Organize notes in a logical hierarchy:

1. **Project Level**: Overall engagement information
   - Client details
   - Scope and objectives
   - Timeline and constraints
   - Rules of engagement

2. **Reconnaissance Level**: Information gathering results
   - OSINT findings
   - Network mapping
   - Target identification
   - Technology stack

3. **Target Level**: Per-host or per-application documentation
   - Open ports and services
   - Vulnerabilities identified
   - Exploitation attempts
   - Post-exploitation activities

4. **Finding Level**: Detailed vulnerability documentation
   - Vulnerability details
   - Proof of concept
   - Impact assessment
   - Remediation recommendations

### Cross-Referencing Techniques

1. **Internal Linking**: Create links between related findings or techniques
2. **External References**: Link to CVEs, exploit databases, or research papers
3. **Timeline Integration**: Map findings to a chronological attack narrative
4. **Attack Path Mapping**: Document the logical progression of the attack

## Digital Note-Taking Tools for Ethical Hackers

### Specialized Security Note-Taking Applications

1. **Cherry Tree**
   - Hierarchical structure
   - Rich text formatting
   - Code syntax highlighting
   - Screenshot embedding
   - Table support

2. **KeepNote**
   - Notebook organization
   - Multi-page documents
   - Attachments support
   - Cross-platform compatibility

3. **Obsidian**
   - Markdown-based
   - Bidirectional linking
   - Graph visualization
   - Local storage
   - Plugin ecosystem

4. **Joplin**
   - End-to-end encryption
   - Markdown support
   - Multi-device synchronization
   - Tag organization
   - Web clipper

### Collaborative Documentation Platforms

1. **GitBook**
   - Version control
   - Collaborative editing
   - Public/private documentation
   - API documentation capabilities
   - Custom domains

2. **Notion**
   - Databases and tables
   - Templates and customization
   - Collaborative features
   - Rich embeds and integrations
   - Web access

3. **Confluence**
   - Enterprise-grade security
   - Extensive collaboration
   - Permission management
   - Version history
   - Integration with Jira

4. **HackMD/CodiMD**
   - Collaborative markdown
   - Real-time editing
   - Code highlighting
   - Presentation mode
   - Version control

## Advanced Note-Taking Best Practices

### Documentation Automation

1. **Command Logging**: Use script command to record terminal sessions
   ```bash
   script -a penetration_test_log.txt
   # Perform commands
   exit
   ```

2. **Output Redirection**: Save command outputs automatically
   ```bash
   nmap -sV 192.168.1.100 | tee nmap_results.txt
   ```

3. **Screenshot Automation**: Use tools like Flameshot for quick captures
   ```bash
   flameshot gui -p ~/pentest/screenshots/
   ```

4. **Custom Scripts**: Develop scripts to format and organize tool outputs
   ```bash
   ./format_nmap.py scan.xml > formatted_scan.md
   ```

### Evidence Collection

1. **Standardized Screenshot Naming**:
   ```
   YYYYMMDD_target_vulnerability_evidence#.png
   ```

2. **Video Recording**: Capture complex exploitation processes
   ```bash
   asciinema rec exploitation_process.cast
   ```

3. **Raw Data Preservation**: Keep original tool outputs alongside formatted notes
   ```
   /evidence/raw/nmap_scan.xml
   /evidence/processed/nmap_findings.md
   ```

4. **Chain of Custody**: Document when and how evidence was collected
   ```
   Evidence ID: EV-2023-001
   Collected by: [Tester Name]
   Date/Time: 2023-05-15 14:30 UTC
   Method: Nmap scan with XML output
   Hash: sha256:[file_hash]
   ```

## Enhanced Documentation for Common Assessment Areas

### Network Scanning Documentation

```markdown
# Network Scan: 192.168.1.0/24
Date: 2023-05-15
Tool: Nmap 7.92

## Command
```bash
nmap -sV -sC -p- --min-rate 5000 -oA network_scan 192.168.1.0/24
```

## Key Findings
- 15 live hosts discovered
- Critical services: Web (7), Database (2), Mail (1)
- Potentially vulnerable services:
  - Apache 2.4.29 (CVE-2021-39275) on 192.168.1.10
  - ProFTPD 1.3.5 (CVE-2015-3306) on 192.168.1.15
  - SMB (CVE-2020-0796) on 192.168.1.20

## Details
[Link to detailed scan results](./raw/network_scan.xml)
```

### Web Application Testing Documentation

```markdown
# Web Application Assessment: example.com
Date: 2023-05-16
Scope: Main application and authenticated admin portal

## Vulnerability: SQL Injection
**Location**: /search.php?term=
**Parameter**: term
**Severity**: High
**CVSS**: 8.5

### Description
The search function is vulnerable to SQL injection, allowing an attacker to extract database contents.

### Proof of Concept
```
/search.php?term=test' UNION SELECT 1,2,3,username,password FROM users-- -
```

### Evidence
![SQL Injection Evidence](./screenshots/sqli_evidence_1.png)

### Impact
Full database access including user credentials.

### Remediation
Implement prepared statements and parameterized queries.
```

## Integrating Findings with Reporting Tools

### Report Generation from Notes

1. **Markdown to PDF/DOCX Conversion**:
   ```bash
   pandoc -f markdown -t pdf -o final_report.pdf pentest_notes.md
   ```

2. **Template-Based Reporting**:
   ```bash
   ./report_gen.py --template executive --input findings/ --output executive_summary.docx
   ```

3. **Automated Evidence Integration**:
   ```bash
   ./evidence_compiler.py --findings findings.json --screenshots ./evidence/ --output report/
   ```

### Maintaining a Vulnerability Database

Create a personal knowledge base of vulnerabilities:

1. **Structure**:
   ```
   /vulndb/web/sqli/
   /vulndb/web/xss/
   /vulndb/network/smb/
   /vulndb/wireless/wpa2/
   ```

2. **Per-Vulnerability Documentation**:
   ```markdown
   # SQL Injection - Error Based
   
   ## Description
   Error-based SQL injection uses database error messages to extract information.
   
   ## Detection Techniques
   - Single quote test: `'`
   - Logic test: `1=1` vs `1=2`
   - Error forcing: `convert(int,@@version)`
   
   ## Exploitation Methods
   ```sql
   ' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) AND '1'='1
   ```
   
   ## References
   - [OWASP](https://owasp.org/www-community/attacks/SQL_Injection)
   - [PortSwigger](https://portswigger.net/web-security/sql-injection/examining-the-database)
   
   ## Past Engagements
   - [Client A - 2023-01-15](../projects/2023/clientA/findings/sqli.md)
   - [Client B - 2023-03-22](../projects/2023/clientB/findings/sqli.md)
   ```

## Version Control for Penetration Testing Notes

### Git-Based Documentation

1. **Repository Structure**:
   ```
   /projects/
     /2023/
       /client_name/
         /reconnaissance/
         /scanning/
         /exploitation/
         /post-exploitation/
         /evidence/
         /report/
   ```

2. **Commit Practices**:
   ```bash
   git commit -m "Add SQL injection finding for admin portal"
   ```

3. **Branching Strategy**:
   ```
   master/main - Stable, verified findings
   working - Current assessment notes
   feature/target-name - Specific target investigation
   ```

4. **Security Considerations**:
   - Local repositories only
   - Full disk encryption
   - No cloud syncing of sensitive data
   - Consider git-crypt for sensitive files

## Balancing Detail and Readability

### Executive Summaries

Include concise summaries at the beginning of each section:

```markdown
## Executive Summary

The assessment of Example Corp's external infrastructure revealed 3 critical, 5 high, and 12 medium-severity vulnerabilities. The most concerning findings include an unauthenticated RCE in the customer portal, exposed credentials in public Git repositories, and outdated VPN software vulnerable to known exploits. These issues could allow an attacker to gain full access to internal systems.

[Detailed findings below]
```

### Technical Details

Provide comprehensive technical information for each finding:

```markdown
### Technical Details

The SQL injection vulnerability in the login form allows extraction of data through time-based techniques. By injecting the following payload:

```sql
username=admin' AND (SELECT SLEEP(5) FROM DUAL WHERE (SELECT SUBSTRING(user(),1,1))='r')-- -
```

We were able to extract the database username character by character. This technique was extended to extract the following information:

- Database version: MySQL 5.7.34
- Database user: root@localhost
- Database names: information_schema, mysql, performance_schema, app_db

Further extraction revealed 237 user credentials in the app_db.users table.
```

## Conclusion

Revisiting and refining your notes throughout a penetration testing engagement leads to more thorough documentation, better reporting, and a valuable knowledge base for future assessments. By implementing advanced note-taking strategies and leveraging appropriate tools, you can transform raw observations into structured, actionable security intelligence.

Remember that the ultimate goal of penetration testing documentation is to clearly communicate security risks and provide actionable remediation guidance. As your ethical hacking skills evolve, your documentation should evolve alongside them, becoming more comprehensive, structured, and valuable to both yourself and the organizations you assess.
