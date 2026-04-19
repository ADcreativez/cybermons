#!/bin/bash
# =============================================================
# CYBERMON v2.1.0 — Automated Setup Script
# Run: bash setup.sh
# =============================================================

set -e  # Exit on any error

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}"
echo "  ██████╗██╗   ██╗██████╗ ███████╗██████╗ ███╗   ███╗ ██████╗ ███╗   ██╗"
echo " ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗████╗ ████║██╔═══██╗████╗  ██║"
echo " ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██╔████╔██║██║   ██║██╔██╗ ██║"
echo " ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██║╚██╔╝██║██║   ██║██║╚██╗██║"
echo " ╚██████╗   ██║   ██████╔╝███████╗██║  ██║██║ ╚═╝ ██║╚██████╔╝██║ ╚████║"
echo "  ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═══╝"
echo -e "  Intelligence Platform v2.1.0 — Setup Script${NC}"
echo ""

# ─────────────────────────────────────────
# STEP 1: System Dependencies
# ─────────────────────────────────────────
echo -e "${YELLOW}[1/5] Checking system dependencies...${NC}"

OS_TYPE="$(uname -s)"
ARCH_TYPE="$(uname -m)"

if [[ "$OS_TYPE" == "Linux" ]]; then
    if command -v apt-get &> /dev/null; then
        echo -e "${CYAN}  → Linux (Debian/Ubuntu) detected. Using apt...${NC}"
        sudo apt update -q
        sudo apt install -y \
            python3 python3-pip python3-venv \
            nmap whois unzip dnsrecon \
            build-essential libssl-dev libffi-dev python3-dev \
            libxml2-dev libxslt-dev \
            curl wget git
    elif command -v yum &> /dev/null; then
        echo -e "${CYAN}  → Linux (RHEL/CentOS) detected. Using yum...${NC}"
        sudo yum install -y python3 nmap whois unzip gcc openssl-devel libffi-devel python3-devel curl wget git
    fi
elif [[ "$OS_TYPE" == "Darwin" ]]; then
    echo -e "${CYAN}  → macOS detected. Checking for Homebrew...${NC}"
    if command -v brew &> /dev/null; then
        brew install python nmap whois unzip curl wget git
    fi
fi

# ─────────────────────────────────────────
# STEP 1.5: Advanced Recon Tools (Local Install)
# ─────────────────────────────────────────
mkdir -p bin
BIN_DIR="$(pwd)/bin"

install_local_tool() {
    local name=$1
    local version=$2
    local url=$3
    local type=$4 # zip or tgz
    
    if [ ! -f "bin/$name" ]; then
        echo -e "${YELLOW}  → Installing $name v$version to $BIN_DIR...${NC}"
        TEMP_DIR=$(mktemp -d)
        curl -sL "$url" -o "$TEMP_DIR/download.$type"
        if [ "$type" == "zip" ]; then
            unzip -q "$TEMP_DIR/download.$type" -d "$TEMP_DIR"
        else
            tar -xzf "$TEMP_DIR/download.tgz" -C "$TEMP_DIR"
        fi
        find "$TEMP_DIR" -type f -name "$name" -exec mv {} "$BIN_DIR/$name" \;
        chmod +x "$BIN_DIR/$name"
        rm -rf "$TEMP_DIR"
        echo -e "${GREEN}  ✓ $name installed locally.${NC}"
    else
        echo -e "${GREEN}  ✓ $name already present in bin/${NC}"
    fi
}

if [[ "$OS_TYPE" == "Linux" && "$ARCH_TYPE" == "x86_64" ]]; then
    install_local_tool "subfinder" "2.6.7" "https://github.com/projectdiscovery/subfinder/releases/download/v2.6.7/subfinder_2.6.7_linux_amd64.zip" "zip"
    install_local_tool "waybackurls" "0.1.0" "https://github.com/tomnomnom/waybackurls/releases/download/v0.1.0/waybackurls-linux-amd64-0.1.0.tgz" "tgz"
elif [[ "$OS_TYPE" == "Darwin" ]]; then
    # On Mac, we'll try brew first, but also support local if brew fails
    if command -v brew &> /dev/null; then
        echo "  → Using Homebrew for Mac tools..."
        brew install subfinder waybackurls nmap whois 2>/dev/null || echo -e "${RED}  ⚠ Brew install failed. Manual local installation of binaries suggested.${NC}"
    else
        # Mac ARM64 Fallback (Architecture check)
        if [[ "$ARCH_TYPE" == "arm64" ]]; then
            install_local_tool "subfinder" "2.6.7" "https://github.com/projectdiscovery/subfinder/releases/download/v2.6.7/subfinder_2.6.7_macOS_arm64.zip" "zip"
        else
             install_local_tool "subfinder" "2.6.7" "https://github.com/projectdiscovery/subfinder/releases/download/v2.6.7/subfinder_2.6.7_macOS_amd64.zip" "zip"
        fi
    fi
fi

echo -e "${GREEN}  ✓ System dependencies check complete${NC}"

# ─────────────────────────────────────────
# STEP 2: Python Virtual Environment
# ─────────────────────────────────────────
echo -e "${YELLOW}[2/5] Setting up Python virtual environment...${NC}"
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo -e "${GREEN}  ✓ Virtual environment created${NC}"
else
    echo -e "${GREEN}  ✓ Virtual environment already exists${NC}"
fi

# Ensure we use the venv's pip and python
./venv/bin/python3 -m pip install --upgrade pip --quiet

# ─────────────────────────────────────────
# STEP 3: Python Requirements
# ─────────────────────────────────────────
echo -e "${YELLOW}[3/5] Installing Python packages from requirements.txt...${NC}"
./venv/bin/python3 -m pip install -r requirements.txt --quiet
echo -e "${GREEN}  ✓ Python packages installed${NC}"

# ─────────────────────────────────────────
# STEP 4: Playwright Chromium Browser
# ─────────────────────────────────────────
echo -e "${YELLOW}[4/5] Installing Playwright Chromium browser...${NC}"
# Use explicit venv python for playwright
./venv/bin/python3 -m playwright install chromium

# install-deps is linux-specific and usually requires sudo
if [[ "$(uname -s)" == "Linux" ]]; then
    sudo ./venv/bin/python3 -m playwright install-deps chromium
fi
echo -e "${GREEN}  ✓ Chromium browser installed${NC}"

# ─────────────────────────────────────────
# STEP 5: Initialize Database
# ─────────────────────────────────────────
echo -e "${YELLOW}[5/5] Initializing database...${NC}"
mkdir -p instance
./venv/bin/python3 -c "
from app import create_app, bootstrap_db
app = create_app()
bootstrap_db(app)
print('Database ready.')
"
echo -e "${GREEN}  ✓ Database initialized${NC}"

# ─────────────────────────────────────────
# DONE
# ─────────────────────────────────────────
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║        CYBERMON SETUP COMPLETE! ✓            ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${CYAN}Default Login Credentials:${NC}"
echo -e "  Username : ${YELLOW}admin${NC}"
echo -e "  Password : ${YELLOW}cybermon2026${NC}"
echo -e "  ${RED}⚠ CHANGE PASSWORD IMMEDIATELY AFTER FIRST LOGIN!${NC}"
echo ""
echo -e "  ${CYAN}Start the app:${NC}"
echo -e "  ${YELLOW}source venv/bin/activate && python3 launcher.py${NC}"
echo ""
echo -e "  ${CYAN}Production mode:${NC}"
echo -e "  ${YELLOW}source venv/bin/activate && gunicorn --workers 4 --bind 0.0.0.0:5050 'app:create_app()'${NC}"
echo ""
