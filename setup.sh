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
            nmap whois unzip \
            build-essential libssl-dev libffi-dev python3-dev \
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
# STEP 1.5: Advanced Recon Tools (Subfinder)
# ─────────────────────────────────────────
if ! command -v subfinder &> /dev/null; then
    echo -e "${YELLOW}[1.5/5] Installing Subfinder...${NC}"
    if [[ "$OS_TYPE" == "Linux" && "$ARCH_TYPE" == "x86_64" ]]; then
        TEMP_DIR=$(mktemp -d)
        SUB_VERSION="2.6.7"
        echo "  → Downloading Subfinder v${SUB_VERSION} for Linux x64..."
        curl -sL "https://github.com/projectdiscovery/subfinder/releases/download/v${SUB_VERSION}/subfinder_${SUB_VERSION}_linux_amd64.zip" -o "$TEMP_DIR/subfinder.zip"
        unzip -q "$TEMP_DIR/subfinder.zip" -d "$TEMP_DIR"
        sudo mv "$TEMP_DIR/subfinder" /usr/local/bin/
        sudo chmod +x /usr/local/bin/subfinder
        rm -rf "$TEMP_DIR"
        echo -e "${GREEN}  ✓ Subfinder installed to /usr/local/bin${NC}"
    elif [[ "$OS_TYPE" == "Darwin" ]]; then
        if command -v brew &> /dev/null; then
            brew install subfinder
        fi
    else
        echo -e "${YELLOW}  ⚠ Manual installation required for Subfinder on this architecture/OS.${NC}"
    fi
else
    echo -e "${GREEN}  ✓ Subfinder already installed${NC}"
fi

# ─────────────────────────────────────────
# STEP 1.6: Historical URL Tools (Waybackurls)
# ─────────────────────────────────────────
if ! command -v waybackurls &> /dev/null; then
    echo -e "${YELLOW}[1.6/5] Installing Waybackurls...${NC}"
    if [[ "$OS_TYPE" == "Linux" && "$ARCH_TYPE" == "x86_64" ]]; then
        TEMP_DIR=$(mktemp -d)
        WAY_VERSION="0.1.0"
        echo "  → Downloading Waybackurls v${WAY_VERSION} for Linux x64..."
        curl -sL "https://github.com/tomnomnom/waybackurls/releases/download/v${WAY_VERSION}/waybackurls-linux-amd64-${WAY_VERSION}.tgz" -o "$TEMP_DIR/waybackurls.tgz"
        tar -xzf "$TEMP_DIR/waybackurls.tgz" -C "$TEMP_DIR"
        sudo mv "$TEMP_DIR/waybackurls" /usr/local/bin/
        sudo chmod +x /usr/local/bin/waybackurls
        rm -rf "$TEMP_DIR"
        echo -e "${GREEN}  ✓ Waybackurls installed to /usr/local/bin${NC}"
    elif [[ "$OS_TYPE" == "Darwin" ]]; then
        if command -v brew &> /dev/null; then
            brew install waybackurls
        fi
    else
        echo -e "${YELLOW}  ⚠ Manual installation required for Waybackurls on this architecture/OS.${NC}"
    fi
else
    echo -e "${GREEN}  ✓ Waybackurls already installed${NC}"
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
