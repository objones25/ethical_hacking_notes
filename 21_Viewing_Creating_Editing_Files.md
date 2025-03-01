# Viewing, Creating, & Editing Files

## File Viewing Commands

### cat
- Purpose: Display contents of a file
- Usage: `cat [filename]`
- Example: `cat /etc/passwd`
- Options:
  - `cat -n [filename]` - Show line numbers
  - `cat file1 file2` - Concatenate and display multiple files

### less
- Purpose: View files with pagination (better for large files)
- Usage: `less [filename]`
- Navigation:
  - Space/Page Down - Next page
  - b/Page Up - Previous page
  - g - Go to beginning of file
  - G - Go to end of file
  - /pattern - Search forward for pattern
  - q - Quit

### head
- Purpose: Display the beginning of a file
- Usage: `head [filename]`
- Options: `head -n 20 [filename]` - Show first 20 lines

### tail
- Purpose: Display the end of a file
- Usage: `tail [filename]`
- Options: 
  - `tail -n 20 [filename]` - Show last 20 lines
  - `tail -f [filename]` - Follow file (update as file grows)

### grep
- Purpose: Search for patterns in files
- Usage: `grep [pattern] [filename]`
- Examples:
  ```bash
  grep "password" /etc/shadow
  grep -i "user" /etc/passwd  # Case-insensitive
  grep -r "admin" /etc/        # Recursive search
  ```
- Common options:
  - `-i` - Case-insensitive
  - `-r` or `-R` - Recursive search
  - `-n` - Show line numbers
  - `-v` - Invert match (show lines that don't match)
  - `-A n` - Show n lines after match
  - `-B n` - Show n lines before match

## File Creation Commands

### touch
- Purpose: Create empty file or update timestamp
- Usage: `touch [filename]`
- Example: `touch newfile.txt`

### echo
- Purpose: Output text, often used with redirection to create files
- Usage: `echo "text" > [filename]` (overwrite) or `echo "text" >> [filename]` (append)
- Examples:
  ```bash
  echo "Hello World" > hello.txt
  echo "Another line" >> hello.txt
  ```

### nano
- Purpose: Simple text editor for creating/editing files
- Usage: `nano [filename]`
- Basic controls:
  - Ctrl+O - Save
  - Ctrl+X - Exit
  - Ctrl+G - Help

### vi/vim
- Purpose: Powerful text editor with modes
- Usage: `vi [filename]` or `vim [filename]`
- Modes:
  - Command mode (default) - Navigate and execute commands
  - Insert mode (press `i`) - Edit text
  - Visual mode (press `v`) - Select text
- Basic commands:
  - `:w` - Save
  - `:q` - Quit
  - `:wq` or `ZZ` - Save and quit
  - `:q!` - Quit without saving
  - `/pattern` - Search forward
  - `n` - Next match
  - `dd` - Delete line
  - `yy` - Copy (yank) line
  - `p` - Paste

## File Manipulation Commands

### cp
- Purpose: Copy files and directories
- Usage: `cp [source] [destination]`
- Options:
  - `-r` - Recursive (for directories)
  - `-i` - Interactive (prompt before overwrite)
- Examples:
  ```bash
  cp file.txt backup.txt
  cp -r directory/ backup_dir/
  ```

### mv
- Purpose: Move or rename files and directories
- Usage: `mv [source] [destination]`
- Examples:
  ```bash
  mv oldname.txt newname.txt  # Rename
  mv file.txt /path/to/dir/   # Move
  ```

### rm
- Purpose: Remove files and directories
- Usage: `rm [filename]`
- Options:
  - `-r` - Recursive (for directories)
  - `-f` - Force (no confirmation)
  - `-i` - Interactive (prompt before deletion)
- Examples:
  ```bash
  rm file.txt
  rm -rf directory/  # BE CAREFUL with this!
  ```

### mkdir
- Purpose: Create directories
- Usage: `mkdir [dirname]`
- Options: `-p` - Create parent directories if needed
- Example: `mkdir -p parent/child/grandchild`

## File Permission Commands

### chmod
- Purpose: Change file permissions
- Usage: `chmod [mode] [filename]`
- Examples:
  ```bash
  chmod 755 script.sh
  chmod u+x script.sh  # Add execute permission for user
  ```

### chown
- Purpose: Change file owner
- Usage: `chown [user]:[group] [filename]`
- Example: `chown root:root file.txt`

## Finding Files

### find
- Purpose: Search for files in a directory hierarchy
- Usage: `find [path] [expression]`
- Examples:
  ```bash
  find / -name "passwd"
  find /home -user john
  find . -type f -mtime -7  # Files modified in last 7 days
  ```

### locate
- Purpose: Find files by name (uses database)
- Usage: `locate [pattern]`
- Example: `locate passwd`
- Note: Run `updatedb` to update the database

## File Information Commands

### file
- Purpose: Determine file type
- Usage: `file [filename]`
- Example: `file document.pdf`

### stat
- Purpose: Display detailed file information
- Usage: `stat [filename]`
- Example: `stat /etc/passwd`

### du
- Purpose: Estimate file space usage
- Usage: `du [options] [filename]`
- Options: `-h` - Human-readable sizes
- Example: `du -h /var/log/`

### wc
- Purpose: Count lines, words, and characters
- Usage: `wc [filename]`
- Options:
  - `-l` - Count lines only
  - `-w` - Count words only
  - `-c` - Count bytes/characters only
- Example: `wc -l /etc/passwd`
