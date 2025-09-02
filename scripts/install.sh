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

# Build the tool
echo "Building ACVA..."
if go build -ldflags="-s -w -X main.Version=1.0.0" -o acva cmd/acva/main.go; then
    chmod +x acva
    echo -e "${GREEN}✓ Build successful${NC}"
else
    echo -e "${RED}✗ Build failed${NC}"
    exit 1
fi

# Install globally
echo "Installing ACVA globally..."
sudo mv acva /usr/local/bin/
echo -e "${GREEN}✓ ACVA installed globally. You can now run 'acva' from anywhere.${NC}"

# Create system-wide environment directory
echo "Creating system-wide environment configuration directory..."
sudo mkdir -p /etc/acva

# Create example environment file
sudo tee /etc/acva/env.example > /dev/null << EOL
# ACVA Environment Configuration
# Copy this file to /etc/acva/env and add your actual API keys
# Get your API keys from: https://aistudio.google.com/app/apikey

# Gemini API Keys
export GEMINI_API_KEY_1=your_api_key_here_1
export GEMINI_API_KEY_2=your_api_key_here_2
export GEMINI_API_KEY_3=your_api_key_here_3
export GEMINI_API_KEY_4=your_api_key_here_4
export GEMINI_API_KEY_5=your_api_key_here_5

# Optional: Proxy settings
# export HTTP_PROXY=http://proxy.example.com:8080
# export HTTPS_PROXY=https://proxy.example.com:8080
EOL

# Create a wrapper script that loads the environment
echo "Creating ACVA wrapper script..."
sudo tee /usr/local/bin/acva-wrapper > /dev/null << 'EOL'
#!/bin/bash
# ACVA wrapper script to load environment variables
if [ -f /etc/acva/env ]; then
    source /etc/acva/env
fi
exec /usr/local/bin/acva "$@"
EOL

sudo chmod +x /usr/local/bin/acva-wrapper

# Create symlink from acva to acva-wrapper
sudo ln -sf /usr/local/bin/acva-wrapper /usr/local/bin/acva

echo -e "${GREEN}✓ Environment configuration example created at /etc/acva/env.example${NC}"

# Instructions for user
echo -e "\n${YELLOW}⚠ Important: To use ACVA, you need to set up your Gemini API keys${NC}"
echo -e "1. Get your API keys from: https://aistudio.google.com/app/apikey"
echo -e "2. Create environment file: sudo cp /etc/acva/env.example /etc/acva/env"
echo -e "3. Edit the file with your actual keys: sudo nano /etc/acva/env"

# Test the installation
echo -e "\nTesting installation..."
if command -v acva &> /dev/null; then
    echo -e "${GREEN}✓ ACVA is now available globally.${NC}"
else
    echo -e "${RED}✗ Installation test failed${NC}"
    exit 1
fi

# Summary
echo -e "\n${GREEN}Installation completed successfully!${NC}"
echo -e "\nTo use ACVA:"
echo -e "1. Set up your API keys as shown above"
echo -e "2. Run: acva --target https://example.com --output reports/ --features all"
echo -e "3. Check reports/ directory for results\n"

echo -e "For GitHub Actions:"
echo -e "1. Set secrets in your GitHub repository: GEMINI_API_KEY_1, GEMINI_API_KEY_2, etc."
echo -e "2. The workflow will automatically use them\n"

echo -e "For documentation: https://github.com/sabbir-lite-0/acva/blob/main/docs/GETTING_STARTED.md"
