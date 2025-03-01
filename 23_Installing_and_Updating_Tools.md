# Installing and Updating Tools

## Package Management Systems

### APT (Debian/Ubuntu/Kali)

#### Basic Commands
- Update package lists:
  ```bash
  sudo apt update
  ```

- Upgrade installed packages:
  ```bash
  sudo apt upgrade
  ```

- Full system upgrade:
  ```bash
  sudo apt full-upgrade
  ```

- Install a package:
  ```bash
  sudo apt install [package_name]
  ```

- Remove a package:
  ```bash
  sudo apt remove [package_name]
  ```

- Remove a package and its configuration files:
  ```bash
  sudo apt purge [package_name]
  ```

- Search for packages:
  ```bash
  apt search [keyword]
  ```

- List installed packages:
  ```bash
  apt list --installed
  ```

- Show package information:
  ```bash
  apt show [package_name]
  ```

#### Advanced APT Usage
- Install multiple packages:
  ```bash
  sudo apt install [package1] [package2] [package3]
  ```

- Install specific version:
  ```bash
  sudo apt install [package_name]=[version]
  ```

- Autoremove unused dependencies:
  ```bash
  sudo apt autoremove
  ```

- Clean up cache:
  ```bash
  sudo apt clean
  sudo apt autoclean
  ```

- Fix broken packages:
  ```bash
  sudo apt --fix-broken install
  ```

### YUM/DNF (CentOS/RHEL/Fedora)

#### Basic Commands
- Update package lists:
  ```bash
  sudo yum check-update
  sudo dnf check-update
  ```

- Upgrade installed packages:
  ```bash
  sudo yum upgrade
  sudo dnf upgrade
  ```

- Install a package:
  ```bash
  sudo yum install [package_name]
  sudo dnf install [package_name]
  ```

- Remove a package:
  ```bash
  sudo yum remove [package_name]
  sudo dnf remove [package_name]
  ```

- Search for packages:
  ```bash
  yum search [keyword]
  dnf search [keyword]
  ```

- List installed packages:
  ```bash
  yum list installed
  dnf list installed
  ```

## Installing Tools from Source

### Basic Process
1. Download source code:
   ```bash
   git clone [repository_url]
   # or
   wget [tarball_url]
   tar -xzvf [tarball_file]
   ```

2. Navigate to source directory:
   ```bash
   cd [source_directory]
   ```

3. Configure, build, and install:
   ```bash
   ./configure
   make
   sudo make install
   ```

### Example: Building a Tool from Source
```bash
# Clone repository
git clone https://github.com/example/tool.git

# Navigate to directory
cd tool

# Build
./configure
make

# Install
sudo make install
```

## Using GitHub for Tool Installation

### Cloning Repositories
```bash
git clone https://github.com/username/repository.git
cd repository
```

### Updating Cloned Repositories
```bash
cd repository
git pull
```

### Using GitHub Releases
```bash
# Download specific release
wget https://github.com/username/repository/releases/download/v1.0/tool-v1.0.tar.gz
tar -xzvf tool-v1.0.tar.gz
```

## Python Package Management

### pip
- Install a package:
  ```bash
  pip install [package_name]
  ```

- Install specific version:
  ```bash
  pip install [package_name]==[version]
  ```

- Upgrade a package:
  ```bash
  pip install --upgrade [package_name]
  ```

- Uninstall a package:
  ```bash
  pip uninstall [package_name]
  ```

- List installed packages:
  ```bash
  pip list
  ```

- Install from requirements file:
  ```bash
  pip install -r requirements.txt
  ```

### Virtual Environments
- Create a virtual environment:
  ```bash
  python -m venv [env_name]
  ```

- Activate virtual environment:
  ```bash
  # Linux/macOS
  source [env_name]/bin/activate
  
  # Windows
  [env_name]\Scripts\activate
  ```

- Deactivate virtual environment:
  ```bash
  deactivate
  ```

## Node.js Package Management

### npm
- Install a package:
  ```bash
  npm install [package_name]
  ```

- Install globally:
  ```bash
  npm install -g [package_name]
  ```

- Update packages:
  ```bash
  npm update
  ```

- Uninstall a package:
  ```bash
  npm uninstall [package_name]
  ```

## Docker for Tools

### Basic Docker Commands
- Pull an image:
  ```bash
  docker pull [image_name]
  ```

- Run a container:
  ```bash
  docker run [options] [image_name]
  ```

- List containers:
  ```bash
  docker ps -a
  ```

- Stop a container:
  ```bash
  docker stop [container_id]
  ```

- Remove a container:
  ```bash
  docker rm [container_id]
  ```

- List images:
  ```bash
  docker images
  ```

### Example: Running a Tool via Docker
```bash
# Pull Metasploit image
docker pull metasploitframework/metasploit-framework

# Run Metasploit
docker run -it metasploitframework/metasploit-framework
```

## Adding Repositories

### Adding APT Repositories
```bash
# Add a repository
sudo add-apt-repository [repository]

# Add a PPA
sudo add-apt-repository ppa:[user]/[ppa-name]

# Update package lists after adding
sudo apt update
```

### Adding Custom Repository Keys
```bash
# Add GPG key
curl -fsSL [key_url] | sudo apt-key add -

# Add repository
echo "deb [arch=amd64] [repository_url] [distribution] [component]" | sudo tee /etc/apt/sources.list.d/custom.list

# Update package lists
sudo apt update
```

## Common Security Tools Installation

### Metasploit Framework
```bash
# Using APT
sudo apt install metasploit-framework

# Manual installation
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
chmod 755 msfinstall
./msfinstall
```

### Nmap
```bash
sudo apt install nmap
```

### Wireshark
```bash
sudo apt install wireshark
```

### Burp Suite
```bash
# Download from website
wget https://portswigger.net/burp/releases/download?product=community&version=2021.8.4&type=Jar -O burpsuite_community.jar

# Run
java -jar burpsuite_community.jar
```

### John the Ripper
```bash
sudo apt install john
```

### Aircrack-ng
```bash
sudo apt install aircrack-ng
```

## Keeping Tools Updated

### Update All Packages
```bash
# Debian-based systems
sudo apt update && sudo apt upgrade -y

# Red Hat-based systems
sudo yum update -y
```

### Update Specific Tools
```bash
# Git repositories
cd [repository_directory]
git pull

# Python packages
pip install --upgrade [package_name]
```

## Troubleshooting Installation Issues

### Dependency Issues
```bash
# Fix broken packages
sudo apt --fix-broken install

# Force install
sudo apt install -f
```

### Permission Issues
```bash
# Change ownership
sudo chown -R [username] [directory]

# Change permissions
sudo chmod +x [file]
```

### Library Issues
```bash
# Update library cache
sudo ldconfig
```

## Backup and Restore Tool Configurations

### Backup Configurations
```bash
# Create backup directory
mkdir -p ~/tool-backups

# Copy configuration files
cp -r ~/.tool_config ~/tool-backups/
```

### Restore Configurations
```bash
# Restore configuration files
cp -r ~/tool-backups/.tool_config ~/
```
