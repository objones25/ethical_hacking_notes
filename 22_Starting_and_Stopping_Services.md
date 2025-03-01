# Starting and Stopping Services

## System Service Management

### systemd (Modern Linux Distributions)

#### systemctl
The primary command for managing services on systemd-based systems:

- Check service status:
  ```bash
  systemctl status [service_name]
  ```

- Start a service:
  ```bash
  systemctl start [service_name]
  ```

- Stop a service:
  ```bash
  systemctl stop [service_name]
  ```

- Restart a service:
  ```bash
  systemctl restart [service_name]
  ```

- Enable a service to start on boot:
  ```bash
  systemctl enable [service_name]
  ```

- Disable a service from starting on boot:
  ```bash
  systemctl disable [service_name]
  ```

- View all running services:
  ```bash
  systemctl list-units --type=service
  ```

- Reload systemd configuration:
  ```bash
  systemctl daemon-reload
  ```

- Example: Start and enable SSH service
  ```bash
  systemctl start ssh
  systemctl enable ssh
  ```

### SysVinit (Legacy Linux Systems)

#### service
For older Linux distributions:

- Start a service:
  ```bash
  service [service_name] start
  ```

- Stop a service:
  ```bash
  service [service_name] stop
  ```

- Restart a service:
  ```bash
  service [service_name] restart
  ```

- Check service status:
  ```bash
  service [service_name] status
  ```

#### init.d scripts
Direct use of init scripts:

- Start a service:
  ```bash
  /etc/init.d/[service_name] start
  ```

- Stop a service:
  ```bash
  /etc/init.d/[service_name] stop
  ```

- Check which services are set to run at boot:
  ```bash
  ls /etc/rc3.d/
  ```

- Managing runlevels:
  ```bash
  update-rc.d [service_name] enable
  update-rc.d [service_name] disable
  ```

## Common Services for Ethical Hacking

### Web Servers

#### Apache
```bash
# Apache on Debian/Ubuntu
systemctl start apache2
systemctl stop apache2
systemctl status apache2

# Apache on CentOS/RHEL
systemctl start httpd
systemctl stop httpd
systemctl status httpd
```

#### Nginx
```bash
systemctl start nginx
systemctl stop nginx
systemctl status nginx
```

### Database Servers

#### MySQL/MariaDB
```bash
systemctl start mysql
systemctl stop mysql
systemctl status mysql

# Alternative on some systems
systemctl start mariadb
systemctl stop mariadb
```

#### PostgreSQL
```bash
systemctl start postgresql
systemctl stop postgresql
systemctl status postgresql
```

### Network Services

#### SSH
```bash
systemctl start ssh
systemctl stop ssh
systemctl status ssh

# On some systems
systemctl start sshd
systemctl stop sshd
```

#### FTP
```bash
# vsftpd
systemctl start vsftpd
systemctl stop vsftpd

# proftpd
systemctl start proftpd
systemctl stop proftpd
```

### Security Tools and Services

#### OpenVAS
```bash
systemctl start openvas
systemctl stop openvas

# Specific components in newer versions
systemctl start gvmd
systemctl start gsad
```

#### Metasploit
```bash
# Start PostgreSQL (required for Metasploit)
systemctl start postgresql

# Start Metasploit database
msfdb init
msfdb start
```

## Process Management

### ps
View running processes:
```bash
# View all processes
ps aux

# View process tree
ps axjf

# Find specific process
ps aux | grep [process_name]
```

### top/htop
Interactive process monitoring:
```bash
top
htop  # More user-friendly alternative
```

### kill
Terminate processes:
```bash
# Kill by PID
kill [PID]

# Force kill
kill -9 [PID]

# Kill by name
killall [process_name]
pkill [process_name]
```

## Network Service Status Commands

### netstat
Check listening ports and connections:
```bash
# Show all listening ports
netstat -tuln

# Show services with PID
netstat -tulnp
```

### ss
Modern replacement for netstat:
```bash
# Show listening ports
ss -tuln

# Show services with process info
ss -tulnp
```

### lsof
List open files and ports:
```bash
# Check which process is using a specific port
lsof -i :80
lsof -i :443
```

## Managing Services via Docker

### Docker Container Management
```bash
# Start a container
docker start [container_name]

# Stop a container
docker stop [container_name]

# Restart a container
docker restart [container_name]

# View running containers
docker ps

# View all containers
docker ps -a
```

## Troubleshooting Services

### Checking logs
```bash
# View system logs
journalctl -xe

# View logs for a specific service
journalctl -u [service_name]

# Follow logs in real-time
journalctl -fu [service_name]

# Traditional log files
cat /var/log/syslog
cat /var/log/messages
```

### Checking configuration
```bash
# Apache configuration test
apachectl configtest

# Nginx configuration test
nginx -t
```

## Examples for Ethical Hacking Tasks

### Setting up a web server for phishing
```bash
systemctl start apache2
cp phishing-page.html /var/www/html/index.html
systemctl restart apache2
```

### Starting necessary services for penetration testing
```bash
# Start PostgreSQL for Metasploit
systemctl start postgresql

# Start SSH for remote connections
systemctl start ssh

# Start Burp Suite (not a system service)
burpsuite &
```

### Setting up a listener with Netcat
```bash
# Create a simple listener on port 4444
nc -lvnp 4444
```
