#!/usr/bin/env bash
# ============================================================================
# AetherRecon — Kali Linux Installer
# ============================================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${CYAN}"
echo "  ╔═══════════════════════════════════════════╗"
echo "  ║     AetherRecon Installer — Kali Linux    ║"
echo "  ╚═══════════════════════════════════════════╝"
echo -e "${NC}"

# Check Python version
PYTHON_VERSION=$(python3 --version 2>/dev/null | awk '{print $2}')
PYTHON_MAJOR=$(echo "$PYTHON_VERSION" | cut -d. -f1)
PYTHON_MINOR=$(echo "$PYTHON_VERSION" | cut -d. -f2)

if [[ "$PYTHON_MAJOR" -lt 3 ]] || [[ "$PYTHON_MINOR" -lt 11 ]]; then
    echo -e "${RED}[✗] Python 3.11+ required. Found: $PYTHON_VERSION${NC}"
    exit 1
fi
echo -e "${GREEN}[✓] Python $PYTHON_VERSION${NC}"

# System dependencies
echo -e "${CYAN}[*] Installing system dependencies...${NC}"
sudo apt-get update -qq
sudo apt-get install -y -qq python3-pip python3-venv whois dnsutils curl git

# Create virtual environment
echo -e "${CYAN}[*] Creating virtual environment...${NC}"
python3 -m venv .venv
source .venv/bin/activate

# Install Python dependencies
echo -e "${CYAN}[*] Installing Python dependencies...${NC}"
pip install --upgrade pip
pip install -r requirements.txt
pip install -e .

# Create output directory
mkdir -p output plugins

# Check for optional tools
echo -e "\n${CYAN}[*] Checking optional tools...${NC}"
TOOLS=(subfinder amass httpx nuclei naabu katana dnsx ffuf assetfinder gau waybackurls nikto)
for tool in "${TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
        echo -e "  ${GREEN}[✓] $tool${NC}"
    else
        echo -e "  ${YELLOW}[–] $tool (not installed, optional)${NC}"
    fi
done

echo -e "\n${GREEN}╔═══════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║     Installation complete!                ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Activate: ${CYAN}source .venv/bin/activate${NC}"
echo -e "  Run:      ${CYAN}aetherrecon scan -t <target> -p safe${NC}"
echo -e "  Help:     ${CYAN}aetherrecon --help${NC}"
echo ""
