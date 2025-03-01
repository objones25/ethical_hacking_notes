# Bash Scripting

## Introduction to Bash Scripting

Bash (Bourne Again SHell) is a command-line interpreter and scripting language used in Linux/Unix environments. Bash scripts allow you to automate tasks, combine commands, and create custom tools for ethical hacking and penetration testing.

### Basic Script Structure

```bash
#!/bin/bash
# This is a comment
# Script description: Simple example script

echo "Hello, world!"

# Execute commands
ls -la
```

### Creating and Running Scripts

1. Create a script file:
   ```bash
   nano myscript.sh
   ```

2. Make it executable:
   ```bash
   chmod +x myscript.sh
   ```

3. Run the script:
   ```bash
   ./myscript.sh
   ```

## Variables and Data Types

### Defining Variables
```bash
# Define variables (no spaces around equals sign)
name="John"
age=30
current_date=$(date)  # Command substitution

# Using variables (prefix with $)
echo "Name: $name"
echo "Age: $age"
echo "Current date: $current_date"
```

### Special Variables
```bash
# $0 - Script name
echo "Script name: $0"

# $1, $2, etc. - Command line arguments
echo "First argument: $1"
echo "Second argument: $2"

# $# - Number of arguments
echo "Number of arguments: $#"

# $@ - All arguments
echo "All arguments: $@"

# $? - Exit status of last command
echo "Exit status: $?"

# $$ - Process ID of current shell
echo "PID: $$"
```

## Input and Output

### Reading User Input
```bash
echo "Enter your name:"
read name

echo "Enter your age:"
read age

echo "Hello, $name! You are $age years old."
```

### Reading Silent Input (for passwords)
```bash
echo "Enter password:"
read -s password
echo "Password accepted."
```

### Reading with Prompt
```bash
read -p "Enter target IP address: " target_ip
echo "Targeting $target_ip"
```

### Output Redirection
```bash
# Redirect stdout to file
echo "This goes to a file" > output.txt

# Append to file
echo "This is appended" >> output.txt

# Redirect stderr to file
command 2> error.log

# Redirect both stdout and stderr
command > all.log 2>&1
```

## Conditional Statements

### if-else Statements
```bash
#!/bin/bash

if [ "$1" = "scan" ]; then
    echo "Performing scan..."
elif [ "$1" = "exploit" ]; then
    echo "Performing exploit..."
else
    echo "Unknown command. Usage: $0 [scan|exploit]"
    exit 1
fi
```

### Numeric Comparisons
```bash
number=10

if [ $number -eq 10 ]; then
    echo "Number equals 10"
fi

if [ $number -gt 5 ]; then
    echo "Number is greater than 5"
fi

if [ $number -lt 20 ]; then
    echo "Number is less than 20"
fi
```

### String Comparisons
```bash
string1="hello"
string2="world"

if [ "$string1" = "hello" ]; then
    echo "String equals hello"
fi

if [ "$string1" != "$string2" ]; then
    echo "Strings are different"
fi

if [ -z "$string1" ]; then
    echo "String is empty"
fi

if [ -n "$string1" ]; then
    echo "String is not empty"
fi
```

### File Conditional Tests
```bash
file="/etc/passwd"

if [ -e "$file" ]; then
    echo "File exists"
fi

if [ -f "$file" ]; then
    echo "Regular file exists"
fi

if [ -d "/etc" ]; then
    echo "Directory exists"
fi

if [ -r "$file" ]; then
    echo "File is readable"
fi

if [ -w "$file" ]; then
    echo "File is writable"
fi

if [ -x "/bin/bash" ]; then
    echo "File is executable"
fi
```

## Loops

### For Loops
```bash
# Basic for loop
for i in 1 2 3 4 5; do
    echo "Number: $i"
done

# Loop through a range
for i in {1..10}; do
    echo "Number: $i"
done

# Loop with step
for i in {10..1..-2}; do  # From 10 to 1, step -2
    echo "Number: $i"
done

# C-style for loop
for ((i=0; i<5; i++)); do
    echo "Index: $i"
done
```

### While Loops
```bash
# Basic while loop
count=1
while [ $count -le 5 ]; do
    echo "Count: $count"
    ((count++))
done

# Read file line by line
while read line; do
    echo "Line: $line"
done < /etc/hosts
```

### Until Loops
```bash
count=1
until [ $count -gt 5 ]; do
    echo "Count: $count"
    ((count++))
done
```

## Functions

### Defining and Calling Functions
```bash
# Define a function
scan_host() {
    echo "Scanning host: $1"
    ping -c 1 "$1" > /dev/null
    if [ $? -eq 0 ]; then
        echo "Host $1 is up"
        return 0
    else
        echo "Host $1 is down"
        return 1
    fi
}

# Call the function
scan_host "8.8.8.8"
```

### Functions with Return Values
```bash
get_status() {
    if ping -c 1 "$1" > /dev/null; then
        return 0  # Success
    else
        return 1  # Failed
    fi
}

get_status "8.8.8.8"
if [ $? -eq 0 ]; then
    echo "Host is reachable"
else
    echo "Host is not reachable"
fi
```

## Arrays

### Defining and Using Arrays
```bash
# Define an array
targets=("192.168.1.1" "192.168.1.2" "192.168.1.3")

# Access array element
echo "First target: ${targets[0]}"

# Array length
echo "Number of targets: ${#targets[@]}"

# Loop through array
for target in "${targets[@]}"; do
    echo "Scanning $target"
    # Add your scanning logic here
done
```

## Practical Examples for Ethical Hacking

### Network Scanning Script
```bash
#!/bin/bash

# Simple ping sweep script
network="192.168.1"

for host in {1..254}; do
    ip="$network.$host"
    ping -c 1 -W 1 "$ip" > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "$ip is up"
    fi
done
```

### Port Scanning Script
```bash
#!/bin/bash

# Simple port scanner
target=$1
start_port=$2
end_port=$3

if [ $# -ne 3 ]; then
    echo "Usage: $0 <target> <start_port> <end_port>"
    exit 1
fi

echo "Scanning ports $start_port to $end_port on $target"

for ((port=$start_port; port<=$end_port; port++)); do
    timeout 1 bash -c "echo > /dev/tcp/$target/$port" 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "Port $port is open"
    fi
done
```

### Automated Reconnaissance Script
```bash
#!/bin/bash

target=$1
output_dir="recon_$target"

if [ $# -ne 1 ]; then
    echo "Usage: $0 <target>"
    exit 1
fi

# Create output directory
mkdir -p "$output_dir"

# Run basic reconnaissance tools
echo "Running nmap scan..."
nmap -sS -A "$target" > "$output_dir/nmap_scan.txt"

echo "Running whois lookup..."
whois "$target" > "$output_dir/whois.txt"

echo "Running host lookup..."
host "$target" > "$output_dir/host.txt"

echo "Reconnaissance completed. Results stored in $output_dir/"
```

## Error Handling

### Basic Error Handling
```bash
#!/bin/bash

# Check if command is available
if ! command -v nmap &> /dev/null; then
    echo "Error: nmap is not installed"
    exit 1
fi

# Run command and check exit status
nmap -sS 192.168.1.1
if [ $? -ne 0 ]; then
    echo "Error: nmap scan failed"
    exit 1
fi

echo "Scan completed successfully"
```

### Custom Error Function
```bash
#!/bin/bash

# Error handling function
error_exit() {
    echo "Error: $1" >&2
    exit 1
}

# Use the function
command || error_exit "Command failed"
```

## Best Practices

1. Always start scripts with a shebang line: `#!/bin/bash`
2. Comment your code for clarity
3. Use meaningful variable names
4. Quote your variables to handle spaces and special characters
5. Use exit codes to indicate success or failure
6. Include error handling for robustness
7. Use functions for reusable code
8. Test extensively before deployment
9. Consider security implications when writing scripts
10. Include usage information for scripts with arguments
