# Users & Privileges (2:28:22)

## User Management Basics

### Types of Users
- **Root User**: Superuser (UID 0) with complete system access
- **System Users**: Created for services and daemons (UID 1-999)
- **Regular Users**: Normal user accounts for people (UID 1000+)

### Important User Files
- `/etc/passwd`: Contains user account information
  - Format: `username:x:UID:GID:comment:home_directory:shell`
- `/etc/shadow`: Contains encrypted passwords
  - Accessible only by root
- `/etc/group`: Contains group information
  - Format: `group_name:x:GID:user_list`

## User Management Commands

### Creating and Modifying Users
1. **adduser/useradd** - Create new users
   ```bash
   sudo adduser username       # Interactive (Debian/Ubuntu)
   sudo useradd username       # Non-interactive (basic)
   ```

2. **usermod** - Modify user accounts
   ```bash
   sudo usermod -aG groupname username    # Add user to group
   sudo usermod -s /bin/bash username     # Change shell
   sudo usermod -L username               # Lock account
   sudo usermod -U username               # Unlock account
   ```

3. **passwd** - Change user passwords
   ```bash
   sudo passwd username        # Change another user's password
   passwd                      # Change your own password
   ```

4. **deluser/userdel** - Delete users
   ```bash
   sudo deluser username       # Delete user
   sudo deluser --remove-home username    # Delete user and home directory
   ```

### Group Management
1. **addgroup/groupadd** - Create new groups
   ```bash
   sudo addgroup groupname     # Interactive (Debian/Ubuntu)
   sudo groupadd groupname     # Non-interactive (basic)
   ```

2. **groupmod** - Modify group properties
   ```bash
   sudo groupmod -n new_name old_name    # Rename group
   ```

3. **delgroup/groupdel** - Delete groups
   ```bash
   sudo delgroup groupname     # Delete group
   ```

4. **groups** - Display user's group memberships
   ```bash
   groups [username]
   ```

## Linux Permissions System

### Permission Types
- **r (read)**: Value 4
- **w (write)**: Value 2
- **x (execute)**: Value 1

### Permission Categories
- **Owner/User (u)**: The user who owns the file
- **Group (g)**: The group associated with the file
- **Others (o)**: Everyone else

### Reading Permissions
```
-rwxr-xr--
```
- First character: File type (- for regular file, d for directory)
- Next three: Owner permissions (rwx)
- Next three: Group permissions (r-x)
- Last three: Others permissions (r--)

### Changing Permissions

1. **chmod** - Change file permissions
   ```bash
   # Octal notation
   chmod 755 file             # rwxr-xr-x

   # Symbolic notation
   chmod u+x file             # Add execute to user
   chmod g-w file             # Remove write from group
   chmod o=r file             # Set others to read only
   chmod a+x file             # Add execute to all
   ```

2. **chown** - Change file owner and group
   ```bash
   chown user file            # Change owner
   chown user:group file      # Change owner and group
   chown :group file          # Change group only
   chown -R user directory    # Recursively change ownership
   ```

### Special Permissions
- **SUID (Set User ID)**: When set on executable files, runs with owner's permissions
  - Octal: 4000
  - Symbolic: `chmod u+s file`
  - Appears as: `-rwsr-xr-x`

- **SGID (Set Group ID)**: When set on executable files, runs with group's permissions
  - Octal: 2000
  - Symbolic: `chmod g+s file`
  - Appears as: `-rwxr-sr-x`

- **Sticky Bit**: Prevents deletion of files by non-owners in writable directories
  - Octal: 1000
  - Symbolic: `chmod +t directory`
  - Appears as: `drwxrwxrwt`

## Privilege Escalation Concepts

### Legitimate Methods
1. **sudo** - Execute commands as another user (typically root)
   ```bash
   sudo command
   sudo -l                    # List available sudo permissions
   ```

2. **su** - Switch user
   ```bash
   su username                # Switch to another user
   su -                       # Switch to root with environment
   ```

3. **pkexec** - Execute commands as another user with Polkit
   ```bash
   pkexec command
   ```

### Security Considerations
- Regularly audit user accounts and privileges
- Follow the principle of least privilege
- Check for unusual SUID/SGID binaries
- Monitor sudo access and usage
- Be cautious with scripts running with elevated privileges

## Importance in Penetration Testing
1. Understanding normal vs. abnormal permissions
2. Identifying privilege escalation vectors
3. Finding misconfigured SUID/SGID binaries
4. Exploiting sudo misconfigurations
5. Leveraging group memberships for access

## Common Privilege Escalation Techniques
1. Exploiting misconfigured sudo permissions
2. Utilizing vulnerable SUID/SGID binaries
3. Leveraging writeable system files
4. Exploiting cron jobs running as privileged users
5. Taking advantage of weak file permissions on sensitive files

## Best Practices
- Set appropriate file permissions
- Limit SUID/SGID binaries
- Configure sudo permissions carefully
- Regularly audit user privileges
- Use groups to organize access control
- Implement proper password policies
