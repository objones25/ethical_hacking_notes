# Navigating the File System (2:10:05)

## Linux File System Basics
- Hierarchical structure starting from root (/)
- Everything in Linux is a file (including directories and devices)
- Case-sensitive file and directory names
- Forward slashes (/) as path separators
- Hidden files and directories start with a dot (.)

## Key Directories
- `/` - Root directory, top of file system hierarchy
- `/home` - User home directories
- `/root` - Home directory for the root user
- `/etc` - System configuration files
- `/bin` - Essential user command binaries
- `/sbin` - System binaries (typically requiring root privileges)
- `/usr` - User programs, libraries, documentation
- `/var` - Variable data (logs, temp files, mail, etc.)
- `/tmp` - Temporary files (cleared upon reboot)
- `/opt` - Optional application software packages
- `/proc` - Virtual filesystem for system information
- `/dev` - Device files
- `/mnt` - Mount point for temporary filesystems
- `/media` - Mount point for removable media

## Essential Navigation Commands

### Basic Navigation
1. **pwd** - Print working directory
   ```bash
   pwd
   ```

2. **ls** - List directory contents
   ```bash
   ls               # Basic listing
   ls -l            # Long format (permissions, size, date)
   ls -la           # Include hidden files
   ls -lh           # Human-readable file sizes
   ls -R            # Recursive listing
   ls -t            # Sort by modification time
   ```

3. **cd** - Change directory
   ```bash
   cd /path/to/directory    # Absolute path
   cd directory             # Relative path
   cd ..                    # Move up one directory
   cd ~                     # Go to home directory
   cd -                     # Return to previous directory
   ```

### File and Directory Operations

1. **mkdir** - Create directories
   ```bash
   mkdir directory_name
   mkdir -p parent/child/grandchild    # Create parent directories as needed
   ```

2. **rmdir** - Remove empty directories
   ```bash
   rmdir directory_name
   ```

3. **rm** - Remove files or directories
   ```bash
   rm file_name
   rm -r directory_name     # Recursive removal
   rm -f file_name          # Force removal without prompting
   rm -rf directory_name    # Force recursive removal (use with caution!)
   ```

4. **cp** - Copy files and directories
   ```bash
   cp source destination
   cp -r source_dir destination_dir    # Recursive copy for directories
   ```

5. **mv** - Move/rename files and directories
   ```bash
   mv source destination
   ```

6. **touch** - Create empty files or update timestamps
   ```bash
   touch file_name
   ```

### Viewing File Content

1. **cat** - Display file contents
   ```bash
   cat file_name
   ```

2. **less** - View files with pagination
   ```bash
   less file_name
   ```
   - Press `q` to quit
   - Press `/` to search, `n` for next match
   - Use arrow keys to navigate

3. **head** - Display first lines of file
   ```bash
   head file_name           # First 10 lines
   head -n 20 file_name     # First 20 lines
   ```

4. **tail** - Display last lines of file
   ```bash
   tail file_name           # Last 10 lines
   tail -n 20 file_name     # Last 20 lines
   tail -f file_name        # Follow file updates (useful for logs)
   ```

### File Searching

1. **find** - Search for files in directory hierarchy
   ```bash
   find /path -name "pattern"          # Find by name
   find /path -type f -name "*.txt"    # Find text files
   find /path -type d -name "dir*"     # Find directories
   find /path -mtime -7                # Files modified in last 7 days
   find /path -size +10M               # Files larger than 10MB
   ```

2. **grep** - Search file contents
   ```bash
   grep "pattern" file_name
   grep -r "pattern" directory         # Recursive search
   grep -i "pattern" file_name         # Case-insensitive
   ```

3. **locate** - Find files by name (uses database)
   ```bash
   locate file_name
   ```
   - Update database with `sudo updatedb`

### File Permission Management

1. **chmod** - Change file permissions
   ```bash
   chmod permissions file_name
   chmod 755 file_name      # User: rwx, Group: r-x, Others: r-x
   chmod +x file_name       # Add execute permission
   ```

2. **chown** - Change file owner
   ```bash
   chown user:group file_name
   ```

## File System Navigation Tips for Penetration Testing

1. Know where to find:
   - System logs: `/var/log`
   - Config files: `/etc`
   - User data: `/home`
   - Web server files: `/var/www` (typically)

2. Important files for enumeration:
   - `/etc/passwd` - User accounts
   - `/etc/shadow` - Password hashes (requires root)
   - `/etc/hosts` - Host mappings
   - `/etc/crontab` - Scheduled tasks

3. Common tool locations in Kali:
   - Most tools accessible via PATH
   - Custom scripts often in `/usr/share/`
   - Tool-specific directories (e.g., `/usr/share/wordlists`)

4. Best practices:
   - Organize findings in structured directories
   - Use absolute paths in scripts
   - Check permissions before accessing sensitive files
   - Create backups before modifying system files
