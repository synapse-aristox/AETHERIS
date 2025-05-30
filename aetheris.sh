#!/bin/bash

# Check if terminal supports Unicode icons
ICON_SUPPORT=true
icon_test="🔍"

if ! printf "$icon_test" | grep -q "🔍"; then
    ICON_SUPPORT=false
fi

# Ask user to install Nerd Font if not supported
if [ "$ICON_SUPPORT" = false ]; then
    echo "Your terminal may not display icons correctly."
    read -p "Would you like to continue without icons? [y/N]: " answer
    case "$answer" in
        [Yy]*) ICON_SUPPORT=false ;;
        *) ICON_SUPPORT=false ;;
    esac
fi

# Function to return icon or empty string
icon() {
    if [ "$ICON_SUPPORT" = true ]; then
        echo "$1"
    else
        echo ""
    fi
}

#!/bin/bash

# Color variables
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Language messages
LANG_MESSAGES_EN=(
    "Invalid option, try again"
    "WARNING: Unauthorized scanning may be illegal. Use responsibly."
    "Enter a name for the target machine (no spaces):"
    "Scan reports will be saved to:"
    "AETHERIS ▸ Reconnaissance. Elegantly Executed"
    "Powered by AETHERIS // Operated by NyxKraken"
)

# Function to test Unicode icon support
detect_icon_support() {
    if echo -e "\u2714" | grep -q "✔"; then
        USE_ICONS=true
    else
        USE_ICONS=false
    fi
}

print_icon() {
    if [ "$USE_ICONS" = true ]; then
        echo -n "$1"
    fi
}

# Detect if Unicode icons can be used
detect_icon_support

# Optional prompt if icons are not supported
if [ "$USE_ICONS" = false ]; then
    echo -e "${YELLOW}Your terminal may not support Unicode icons.${NC}"
    read -p "Would you like to install a Nerd Font for full visual support? (y/n): " choice
    if [[ "$choice" =~ ^[Yy]$ ]]; then
        echo -e "${CYAN}Visit https://www.nerdfonts.com/font-downloads to install fonts like FiraCode Nerd Font.${NC}"
        echo -e "${YELLOW}Restart your terminal after installing the font to see full icons.${NC}"
    fi
fi

# Banner
echo -e "\n${BLUE}+-+-+-+-+-+-+-+-+-+${NC}"
echo -e "${CYAN}|A|E|T|H|E|R|I|S|${NC}"
echo -e "${BLUE}+-+-+-+-+-+-+-+-+-+${NC}"
echo -e "${YELLOW}:: ${LANG_MESSAGES_EN[4]} ::${NC}"
echo -e "${YELLOW}:: ${LANG_MESSAGES_EN[5]} ::\n${NC}"

# Minimal example menu
echo -e "${BLUE}──────────────────────────────────────────────${NC}"
echo -e "${CYAN}Main Menu${NC}"
print_icon "$(icon "🧭") "; echo "1) Full Scan"
print_icon "$(icon "🔐") "; echo "2) SSH Enumeration"
print_icon "📁 "; echo "3) Exit"
echo -e "${BLUE}──────────────────────────────────────────────${NC}"

read -p "Choose an option [1-3]: " option

# Simulated actions
case $option in
    1) echo "Launching Full Scan...";;
    2) echo "Enumerating SSH...";;
    3) echo "Exiting..."; exit;;
    *) echo "${RED}${LANG_MESSAGES_EN[0]}${NC}";;
esac
