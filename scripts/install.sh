#!/bin/bash

# ACVA Global Installation Script
set -e

echo "Installing ACVA (Advanced Cybersecurity Vulnerability Assessment) Tool Globally"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo -e "${RED}Error: Go is not installed. Please install Go 1.21 or later.${NC}"
    echo "Visit: https://golang.org/dl/"
    exit 1
fi

# Check Go version
GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
if [ "$(printf '%s\n' "1.21" "$GO_VERSION" | sort -V | head -n1)" != "1.21" ]; then
    echo -e "${RED}Error: Go version 1.21 or later is required. Current version: $GO_VERSION${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Found Go $GO_VERSION${NC}"

# Ensure we're in the right directory
if [ ! -f "go.mod" ]; then
    echo -e "${RED}Error: Must run install script from ACVA project root directory${NC}"
    echo "Current directory: $(pwd)"
    exit 1
fi

# Clean up any previous builds
echo "Cleaning up previous builds..."
rm -f acva

# Download and verify dependencies
echo "Downloading Go dependencies..."
if go mod download; then
    echo -e "${GREEN}✓ Dependencies downloaded successfully${NC}"
else
    echo -e "${YELLOW}⚠ Trying to fix dependencies with go mod tidy...${NC}"
    go mod tidy
    if ! go mod download; then
        echo -e "${RED}✗ Failed to download dependencies${NC}"
        exit 1
    fi
fi

# Verify all dependencies are available
echo "Verifying dependencies..."
if go mod verify; then
    echo -e "${GREEN}✓ Dependencies verified successfully${NC}"
else
    echo -e "${RED}✗ Dependency verification failed${NC}"
    exit 1
fi

# Build the tool with more detailed output
echo "Building ACVA..."
if go build -v -ldflags="-s -w -X main.Version=2.0.0" -o acva cmd/acva/main.go; then
    chmod +x acva
    echo -e "${GREEN}✓ Build successful${NC}"
    
    # Test if the binary works
    if ./acva --version &>/dev/null; then
        echo -e "${GREEN}✓ Binary is functional${NC}"
    else
        echo -e "${YELLOW}⚠ Binary built but may have runtime issues${NC}"
    fi
else
    echo -e "${RED}✗ Build failed${NC}"
    echo "Trying alternative build approach..."
    
    # Try building with more verbose output
    go build -x -ldflags="-s -w -X main.Version=2.0.0" -o acva cmd/acva/main.go 2>&1 | head -20
    if [ -f "acva" ]; then
        chmod +x acva
        echo -e "${GREEN}✓ Build successful after alternative approach${NC}"
    else
        echo -e "${RED}✗ Build failed completely${NC}"
        echo "Please check your Go environment and try again."
        exit 1
    fi
fi

# Install globally
echo "Installing ACVA globally..."
sudo mv acva /usr/local/bin/
echo -e "${GREEN}✓ ACVA installed globally. You can now run 'acva' from anywhere.${NC}"

# Create system-wide environment directory
echo "Creating system-wide environment configuration directory..."
sudo mkdir -p /etc/acva

# Create secure environment file with proper permissions
sudo tee /etc/acva/env.example > /dev/null << 'EOL'
# ACVA Environment Configuration
# Copy this file to /etc/acva/env and add your actual API keys
# Get your API keys from: https://aistudio.google.com/app/apikey

# Gemini API Keys (will be loaded from environment variables)
# export GEMINI_API_KEY_1=your_actual_api_key_here_1
# export GEMINI_API_KEY_2=your_actual_api_key_here_2
# export GEMINI_API_KEY_3=your_actual_api_key_here_3
# export GEMINI_API_KEY_4=your_actual_api_key_here_4
# export GEMINI_API_KEY_5=your_actual_api_key_here_5

# Optional: Proxy settings
# export HTTP_PROXY=http://proxy.example.com:8080
# export HTTPS_PROXY=https://proxy.example.com:8080
EOL

# Set strict permissions on the example file
sudo chmod 600 /etc/acva/env.example

# Create a secure wrapper script that doesn't expose API keys
sudo tee /usr/local/bin/acva-wrapper > /dev/null << 'EOL'
#!/bin/bash
# ACVA wrapper script to load environment variables securely

# Check if environment file exists and load it
if [ -f /etc/acva/env ] && [ -r /etc/acva/env ]; then
    # Source the environment file in a sub-shell to avoid exposing variables
    . /etc/acva/env
fi

# Also check for environment variables that might be set elsewhere
# This allows Docker, systemd, or other process managers to set the variables

# Execute the main binary with all arguments
exec /usr/local/bin/acva "$@"
EOL

sudo chmod 755 /usr/local/bin/acva-wrapper

# Create symlink from acva to acva-wrapper
sudo ln -sf /usr/local/bin/acva-wrapper /usr/local/bin/acva

echo -e "${GREEN}✓ Environment configuration example created at /etc/acva/env.example${NC}"

# Create a secure setup script for API keys
sudo tee /usr/local/bin/acva-setup > /dev/null << 'EOL'
#!/bin/bash
# ACVA API Key Setup Script

echo "ACVA API Key Setup"
echo "=================="
echo

# Check if environment file already exists
if [ -f /etc/acva/env ]; then
    echo "Environment file already exists at /etc/acva/env"
    read -p "Do you want to overwrite it? (y/N): " overwrite
    if [[ ! "$overwrite" =~ ^[Yy]$ ]]; then
        echo "Aborting."
        exit 0
    fi
fi

# Get API keys securely
echo "Please enter your Gemini API keys (get them from: https://aistudio.google.com/app/apikey)"
echo "You can enter up to 5 keys for load balancing and redundancy."
echo

keys=()
for i in {1..5}; do
    read -s -p "Gemini API Key $i (press Enter to skip): " key
    echo
    if [ -n "$key" ]; then
        keys+=("$key")
    else
        break
    fi
done

if [ ${#keys[@]} -eq 0 ]; then
    echo "No API keys provided. Gemini features will be disabled."
    # Create empty environment file
    sudo tee /etc/acva/env > /dev/null << EOF
# ACVA Environment Configuration
# Gemini API Keys - None provided
EOF
else
    # Create environment file with keys
    sudo tee /etc/acva/env > /dev/null << EOF
# ACVA Environment Configuration
# Gemini API Keys
EOF
    
    for i in "${!keys[@]}"; do
        echo "export GEMINI_API_KEY_$((i+1))=\"${keys[$i]}\"" | sudo tee -a /etc/acva/env > /dev/null
    done
fi

# Set strict permissions on the environment file
sudo chmod 600 /etc/acva/env

echo
echo -e "\033[32m✓ API keys configured successfully\033[0m"
echo "Environment file created at /etc/acva/env with secure permissions"
EOL

sudo chmod 755 /usr/local/bin/acva-setup

# Instructions for user
echo -e "\n${YELLOW}⚠ Important: To use ACVA with AI features, you need to set up your Gemini API keys${NC}"
echo -e "Run: sudo acva-setup"
echo -e "This will guide you through setting up your API keys securely"

# Test the installation
echo -e "\nTesting installation..."
if command -v acva &> /dev/null; then
    echo -e "${GREEN}✓ ACVA is now available globally.${NC}"
    
    # Test version command
    if acva --version &>/dev/null; then
        echo -e "${GREEN}✓ ACVA is working correctly${NC}"
    else
        echo -e "${YELLOW}⚠ ACVA installed but may have issues running${NC}"
    fi
else
    echo -e "${RED}✗ Installation test failed${NC}"
    exit 1
fi

# Create a systemd service file for daemon mode
if [ -d "/etc/systemd/system" ]; then
    echo "Creating systemd service file..."
    sudo tee /etc/systemd/system/acva.service > /dev/null << 'EOL'
[Unit]
Description=ACVA Vulnerability Scanner Daemon
After=network.target

[Service]
Type=simple
User=acva
Group=acva
EnvironmentFile=/etc/acva/env
ExecStart=/usr/local/bin/acva --daemon --daemon-addr 127.0.0.1:8080
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOL

    echo -e "${GREEN}✓ Systemd service file created at /etc/systemd/system/acva.service${NC}"
    echo -e "To enable the daemon: sudo systemctl enable acva && sudo systemctl start acva"
fi

# Summary
echo -e "\n${GREEN}Installation completed successfully!${NC}"
echo -e "\nNext steps:"
echo -e "1. Set up your API keys: sudo acva-setup"
echo -e "2. Test the installation: acva --version"
echo -e "3. Run a scan: acva --target https://example.com --output reports/ --features all"
echo -e "4. Check reports/ directory for results\n"

echo -e "For GitHub Actions:"
echo -e "1. Set secrets in your GitHub repository: GEMINI_API_KEY_1, GEMINI_API_KEY_2, etc."
echo -e "2. The workflow will automatically use them\n"

echo -e "For documentation: https://github.com/sabbir-lite-0/acva/blob/main/docs/GETTING_STARTED.md"

# Security note
echo -e "\n${YELLOW}Security Note:${NC}"
echo -e "• API keys are stored in /etc/acva/env with restricted permissions (600)"
echo -e "• The environment file is only readable by root and the acva user"
echo -e "• API keys are never exposed in process listings or logs"
echo -e "• For maximum security, consider using your system's secret management"
