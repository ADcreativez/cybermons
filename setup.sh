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
echo -e "${YELLOW}[1/5] Installing system dependencies...${NC}"
sudo apt update -q
sudo apt install -y \
    python3 python3-pip python3-venv \
    nmap \
    build-essential libssl-dev libffi-dev python3-dev \
    curl wget git
echo -e "${GREEN}  ✓ System dependencies installed (including nmap)${NC}"

# ─────────────────────────────────────────
# STEP 1: System Dependencies
# ─────────────────────────────────────────
echo -e "${YELLOW}[1/5] Checking system dependencies...${NC}"

OS_TYPE="$(uname -s)"

if [[ "$OS_TYPE" == "Linux" ]]; then
    if command -v apt-get &> /dev/null; then
        echo -e "${CYAN}  → Linux (Debian/Ubuntu) detected. Using apt...${NC}"
        sudo apt update -q
        sudo apt install -y \
            python3 python3-pip python3-venv \
            nmap \
            build-essential libssl-dev libffi-dev python3-dev \
            curl wget git
    elif command -v yum &> /dev/null; then
        echo -e "${CYAN}  → Linux (RHEL/CentOS) detected. Using yum...${NC}"
        sudo yum install -y python3 nmap gcc openssl-devel libffi-devel python3-devel curl wget git
    else
        echo -e "${YELLOW}  ⚠ Unsupported Linux distribution. Please ensure dependencies are installed manually.${NC}"
    fi
elif [[ "$OS_TYPE" == "Darwin" ]]; then
    echo -e "${CYAN}  → macOS detected. Checking for Homebrew...${NC}"
    if command -v brew &> /dev/null; then
        brew install python nmap curl wget git
    else
        echo -e "${YELLOW}  ⚠ Homebrew not found. Skipping system package installation.${NC}"
    fi
else
    echo -e "${YELLOW}  ⚠ Unsupported OS: $OS_TYPE. Skipping system package installation.${NC}"
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

source venv/bin/activate
pip install --upgrade pip --quiet

# ─────────────────────────────────────────
# STEP 3: Python Requirements
# ─────────────────────────────────────────
echo -e "${YELLOW}[3/5] Installing Python packages from requirements.txt...${NC}"
pip install -r requirements.txt --quiet
echo -e "${GREEN}  ✓ Python packages installed${NC}"

# ─────────────────────────────────────────
# STEP 4: Playwright Chromium Browser
# ─────────────────────────────────────────
echo -e "${YELLOW}[4/5] Installing Playwright Chromium browser...${NC}"
# Use current python within venv for playwright
python3 -m playwright install chromium

# install-deps is linux-specific and usually requires sudo
if [[ "$(uname -s)" == "Linux" ]]; then
    sudo python3 -m playwright install-deps chromium
fi
echo -e "${GREEN}  ✓ Chromium browser installed${NC}"

# ─────────────────────────────────────────
# STEP 5: Initialize Database
# ─────────────────────────────────────────
echo -e "${YELLOW}[5/5] Initializing database...${NC}"
mkdir -p instance
python3 -c "
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
