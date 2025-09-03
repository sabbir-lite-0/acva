#!/bin/bash

# ACVA Installation Script
set -e

echo "Installing ACVA (Advanced Cybersecurity Vulnerability Assessment) Tool"

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

# Create directory structure
echo "Creating directory structure..."
mkdir -p {reports,logs,wordlists,config}

# Download default wordlists if wget is available
if command -v wget &> /dev/null; then
    echo "Downloading wordlists..."
    
    WORDLISTS=(
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt"
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt"
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-words.txt"
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints.txt"
    )
    
    for url in "${WORDLISTS[@]}"; do
        filename=$(basename "$url")
        echo "Downloading $filename..."
        wget -q -O "wordlists/$filename" "$url" || echo "Failed to download $filename"
    done
    
    echo -e "${GREEN}✓ Wordlists downloaded${NC}"
else
    echo -e "${YELLOW}⚠ wget not found. Please manually download wordlists to the wordlists/ directory.${NC}"
fi

# Build the tool - FIXED COMMAND
echo "Building ACVA..."
if go build -ldflags="-s -w -X main.Version=1.0.0" -o acva ./cmd/acva; then
    chmod +x acva
    echo -e "${GREEN}✓ Build successful${NC}"
else
    echo -e "${RED}✗ Build failed${NC}"
    exit 1
fi

# Ask user if they want to install globally
read -p "Do you want to install ACVA globally? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    # Check if /usr/local/bin exists and is writable
    if [ -w /usr/local/bin ]; then
        sudo mv acva /usr/local/bin/
        echo -e "${GREEN}✓ ACVA installed globally. You can now run 'acva' from anywhere.${NC}"
    else
        echo -e "${YELLOW}⚠ /usr/local/bin is not writable. Trying with sudo...${NC}"
        sudo mv acva /usr/local/bin/
        echo -e "${GREEN}✓ ACVA installed globally with sudo. You can now run 'acva' from anywhere.${NC}"
    fi
else
    echo -e "${YELLOW}ACVA binary is available in the current directory. Use './acva' to run it.${NC}"
fi

# Create default config if it doesn't exist
if [ ! -f config/config.yaml ]; then
    echo "Creating default configuration..."
    cp configs/config.yaml config/
fi

# Create .env.example if it doesn't exist
if [ ! -f .env.example ]; then
    echo "Creating .env.example file..."
    cat > .env.example << EOL
# Gemini API Keys (at least one required)
# Get your API keys from: https://aistudio.google.com/app/apikey
GEMINI_API_KEY_1=your_first_api_key_here
GEMINI_API_KEY_2=your_second_api_key_here
GEMINI_API_KEY_3=your_third_api_key_here
GEMINI_API_KEY_4=your_fourth_api_key_here
GEMINI_API_KEY_5=your_fifth_api_key_here

# Optional: Proxy configuration
# HTTP_PROXY=http://proxy.example.com:8080
# HTTPS_PROXY=https://proxy.example.com:8080

# Optional: Custom settings
# ACVA_MAX_SCAN_DURATION=3600
# ACVA_CONCURRENT_REQUESTS=10
EOL
fi

# GitHub Secrets setup information
echo -e "\n${YELLOW}⚠ GitHub Secrets Setup Required:${NC}"
echo -e "To use ACVA with GitHub Actions, you need to set up these secrets in your GitHub repository:"
echo -e "1. Go to your GitHub repository Settings -> Secrets and variables -> Actions"
echo -e "2. Add the following secrets:"
echo -e "   - GEMINI_API_KEY_1"
echo -e "   - GEMINI_API_KEY_2"
echo -e "   - GEMINI_API_KEY_3"
echo -e "   - GEMINI_API_KEY_4"
echo -e "   - GEMINI_API_KEY_5"
echo -e "3. Get your API keys from: https://aistudio.google.com/app/apikey"

# Summary
echo -e "\n${GREEN}Installation completed successfully!${NC}"
echo -e "\nNext steps:"
echo -e "1. For GitHub Actions: Set up the secrets as shown above"
echo -e "2. For local usage:"
echo -e "   - Copy .env.example to .env"
echo -e "   - Edit .env with your actual API keys from https://aistudio.google.com/app/apikey"
echo -e "   - Or set environment variables manually"
echo -e "3. Review config/config.yaml for your needs"
echo -e "4. Run: acva --target https://example.com --output reports/ --features all"
echo -e "5. Check reports/ directory for results\n"

echo -e "For documentation: https://github.com/sabbir-lite-0/acva/docs/GETTING_STARTED.md"
