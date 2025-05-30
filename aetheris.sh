#!/bin/bash

# ==============================
# AETHERIS ▸ Network Scanner
# Minimalist | Ethical | Precise
# ==============================

# ─── Terminal Color Setup ─────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# ─── Icon Support Detection ───────────────────────────────────────────────────
USE_ICONS=true
if ! echo -e "\u2714" | grep -q "✔"; then
    USE_ICONS=false
fi

# ─── Function: Print icon only if supported ───────────────────────────────────
icon() {
    if [ "$USE_ICONS" = true ]; then
        echo -n "$1 " # Added a space after the icon for better readability
    else
        echo -n ""
    fi
}

# --- Language Configuration ---
# Declare associative arrays for translations
declare -A LANG_WARNING
declare -A LANG_MENU_TITLE
declare -A LANG_MENU_OPTIONS
declare -A LANG_MESSAGES
declare -A LANG_QUOTES
declare -A LANG_FOOTER
declare -A LANG_ICON_PROMPTS # New array for icon-related messages

# Function to load English texts
load_english_lang() {
    LANG_WARNING["ethical"]="[!] WARNING: Unauthorized scanning may be illegal. Use responsibly."
    LANG_MENU_TITLE=":: AETHERIS ▸ Reconnaissance. Elegantly Executed ::"
    LANG_MENU_OPTIONS=(
        "Full reconnaissance (top 1000 ports, OS & service detection)"
        "Exhaustive scan (all 65535 ports, OS & service detection)"
        "Local subnet host discovery"
        "SMB enumeration"
        "HTTP vulnerability scan (basic scripts)"
        "FTP vulnerability scan (basic scripts)"
        "SSH enumeration (basic scripts)"
        "Custom Nmap Scan (Advanced)"
        "Generate HTML Report from XML"
        "Exit"
    )
    LANG_MESSAGES["prompt_target_name"]="Enter target machine name (no spaces):"
    LANG_MESSAGES["invalid_target_name"]="[!] Invalid target name. Please enter a name without spaces and ensure it's not empty."
    LANG_MESSAGES["reports_saved_to"]="Scan reports will be saved to:"
    LANG_MESSAGES["failed_dir_creation"]="[!] Failed to create session directory. Exiting."
    LANG_MESSAGES["tool_not_installed"]="[!] Required tool '$tool' is not installed. This script cannot function without it."
    LANG_MESSAGES["install_tool"]="Please install '$tool' (e.g. 'sudo apt install $tool' on Debian/Ubuntu)."
    LANG_MESSAGES["tool_available"]="[✔] $tool is available."
    LANG_MESSAGES["starting_nmap_scan"]="Starting Nmap scan for"
    LANG_MESSAGES["command_to_execute"]="Command to execute:"
    LANG_MESSAGES["scan_completed_success"]="[✔] Scan '$scan_name' completed successfully."
    LANG_MESSAGES["scan_failed"]="[!] Nmap scan failed or encountered errors."
    LANG_MESSAGES["quick_summary"]="--- Quick Summary ---"
    LANG_MESSAGES["hosts_active"]="Hosts active:"
    LANG_MESSAGES["host"]="Host:"
    LANG_MESSAGES["port"]="Port:"
    LANG_MESSAGES["unknown"]="unknown"
    LANG_MESSAGES["xml_file_not_found"]="[!] XML file not found for summary:"
    LANG_MESSAGES["prompt_subnet"]="Enter target subnet (e.g., 192.168.1.0/24):"
    LANG_MESSAGES["invalid_subnet_format"]="[!] Invalid subnet format. Please use the format x.x.x.x/xx."
    LANG_MESSAGES["starting_exhaustive_scan"]="Starting exhaustive scan (this may take a considerable amount of time)..."
    LANG_MESSAGES["discovering_local_hosts"]="Discovering hosts on the local network (sudo is recommended for full host discovery)."
    LANG_MESSAGES["prompt_local_subnet_discovery"]="Enter local subnet for discovery (e.g., 192.168.1.0/24):"
    LANG_MESSAGES["executing_nmap_discovery"]="Executing Nmap for host discovery..."
    LANG_MESSAGES["host_discovery_complete"]="[✔] Host discovery completed."
    LANG_MESSAGES["hosts_found"]="Hosts found:"
    LANG_MESSAGES["use_these_ips"]="You can use these IPs for more detailed scans."
    LANG_MESSAGES["host_discovery_failed"]="[!] Host discovery failed."
    LANG_MESSAGES["prompt_ip_target"]="Enter target IP for"
    LANG_MESSAGES["invalid_ip_format"]="[!] Invalid IP address format. Please use the format x.x.x.x."
    LANG_MESSAGES["prompt_http_ports"]="Enter HTTP ports (e.g., 80,443,8080 or leave blank for default 80,443,8000,8080):"
    LANG_MESSAGES["invalid_port_format"]="[!] Invalid port format. Please use comma-separated numbers (e.g., 80,443) or a range (e.g., 80-90) or leave blank."
    LANG_MESSAGES["prompt_ftp_ports"]="Enter FTP ports (e.g., 21 or leave blank for default 21):"
    LANG_MESSAGES["prompt_ssh_ports"]="Enter SSH ports (e.g., 22 or leave blank for default 22):"
    LANG_MESSAGES["prompt_custom_target"]="Enter target IP or subnet (e.g., 192.168.1.1 or 192.168.1.0/24):"
    LANG_MESSAGES["invalid_target_format"]="[!] Invalid target format. Please enter a valid IP or subnet."
    LANG_MESSAGES["prompt_custom_nmap_args"]="Enter custom Nmap arguments (e.g., -p 22,80 -sV -A):"
    LANG_MESSAGES["generating_html_report"]="Generating HTML report..."
    LANG_MESSAGES["no_xml_found"]="[!] No Nmap XML files found in '$SCAN_SESSION_DIR'."
    LANG_MESSAGES["run_scan_first"]="Please run a scan first."
    LANG_MESSAGES["xml_files_found"]="XML files found in '$SCAN_SESSION_DIR':"
    LANG_MESSAGES["generating_html_for"]="Generating HTML for '$xml_file_path' to '$output_html'"
    LANG_MESSAGES["html_generated_success"]="[✔] HTML report generated successfully: ${output_html}"
    LANG_MESSAGES["open_in_browser"]="You can open it in your web browser."
    LANG_MESSAGES["html_generation_failed"]="[!] HTML report generation failed."
    LANG_MESSAGES["invalid_option_menu"]="Choose an option" # Separate string for menu prompt
    LANG_MESSAGES["invalid_option_error"]="❌ Invalid option" # Separate string for invalid option error
    LANG_MESSAGES["exiting_reports_saved"]="Exiting. Reports saved to $SCAN_SESSION_DIR"
    LANG_MESSAGES["exiting_message"]=":: Exiting AETHERIS. Until next recon. ::"


    LANG_QUOTES=(
        "The stars are silent. Yet they watch."
        "In the dark, precision is your only ally."
        "Recon is not noise, it's poetry in silence."
        "What cannot be seen, cannot be stopped."
    )
    LANG_FOOTER=":: Powered by AETHERIS // Operated by NyxKraken ::"

    LANG_ICON_PROMPTS["unicode_warning"]="⚠️ Your terminal may not support Unicode icons."
    LANG_ICON_PROMPTS["install_nerdfont_prompt"]="Would you like to install a Nerd Font for better visuals? (y/n):"
    LANG_ICON_PROMPTS["download_nerdfont_link"]="👉 Download fonts like FiraCode Nerd Font at:"
    LANG_ICON_PROMPTS["restart_terminal_tip"]="💡 Restart your terminal after installation to apply changes."
}

# Function to load Spanish texts
load_spanish_lang() {
    LANG_WARNING["ethical"]="[!] ADVERTENCIA: El escaneo no autorizado puede ser ilegal. Use con responsabilidad."
    LANG_MENU_TITLE=":: AETHERIS ▸ Reconocimiento. Ejecución Elegante ::"
    LANG_MENU_OPTIONS=(
        "Reconocimiento completo (top 1000 puertos, detección de SO y servicios)"
        "Escaneo exhaustivo (todos los 65535 puertos, detección de SO y servicios)"
        "Descubrimiento de hosts en subred local"
        "Enumeración SMB"
        "Escaneo de vulnerabilidades HTTP (scripts básicos)"
        "Escaneo de vulnerabilidades FTP (scripts básicos)"
        "Enumeración SSH (scripts básicos)"
        "Escaneo Nmap Personalizado (Avanzado)"
        "Generar Informe HTML desde XML"
        "Salir"
    )
    LANG_MESSAGES["prompt_target_name"]="Introduce un nombre para la máquina objetivo (sin espacios):"
    LANG_MESSAGES["invalid_target_name"]="[!] Nombre de objetivo inválido. Por favor, introduce un nombre sin espacios y asegúrate de que no esté vacío."
    LANG_MESSAGES["reports_saved_to"]="Los informes de escaneo se guardarán en:"
    LANG_MESSAGES["failed_dir_creation"]="[!] Falló la creación del directorio de sesión. Saliendo."
    LANG_MESSAGES["tool_not_installed"]="[!] Herramienta requerida '$tool' no está instalada. Este script no puede funcionar sin ella."
    LANG_MESSAGES["install_tool"]="Por favor, instale '$tool' (ej. 'sudo apt install $tool' en Debian/Ubuntu)."
    LANG_MESSAGES["tool_available"]="[✔] $tool está disponible."
    LANG_MESSAGES["starting_nmap_scan"]="Iniciando escaneo Nmap para"
    LANG_MESSAGES["command_to_execute"]="Comando a ejecutar:"
    LANG_MESSAGES["scan_completed_success"]="[✔] Escaneo '$scan_name' completado exitosamente."
    LANG_MESSAGES["scan_failed"]="[!] El escaneo Nmap falló o encontró errores."
    LANG_MESSAGES["quick_summary"]="--- Resumen Rápido ---"
    LANG_MESSAGES["hosts_active"]="Hosts activos:"
    LANG_MESSAGES["host"]="Host:"
    LANG_MESSAGES["port"]="Puerto:"
    LANG_MESSAGES["unknown"]="desconocido"
    LANG_MESSAGES["xml_file_not_found"]="[!] Archivo XML no encontrado para el resumen:"
    LANG_MESSAGES["prompt_subnet"]="Introduce la subred objetivo (ej: 192.168.1.0/24):"
    LANG_MESSAGES["invalid_subnet_format"]="[!] Formato de subred inválido. Por favor, usa el formato x.x.x.x/xx."
    LANG_MESSAGES["starting_exhaustive_scan"]="Iniciando escaneo exhaustivo (esto puede tomar un tiempo considerable)..."
    LANG_MESSAGES["discovering_local_hosts"]="Descubriendo hosts en la red local (se recomienda usar sudo para obtener todos los hosts)."
    LANG_MESSAGES["prompt_local_subnet_discovery"]="Introduce la subred local para descubrimiento (ej: 192.168.1.0/24):"
    LANG_MESSAGES["executing_nmap_discovery"]="Ejecutando Nmap para descubrimiento de hosts..."
    LANG_MESSAGES["host_discovery_complete"]="[✔] Descubrimiento de hosts completado."
    LANG_MESSAGES["hosts_found"]="Hosts encontrados:"
    LANG_MESSAGES["use_these_ips"]="Puede usar estas IPs para escaneos más detallados."
    LANG_MESSAGES["host_discovery_failed"]="[!] El descubrimiento de hosts falló."
    LANG_MESSAGES["prompt_ip_target"]="Introduce la IP objetivo para escaneo"
    LANG_MESSAGES["invalid_ip_format"]="[!] Formato de IP inválido. Por favor, usa el formato x.x.x.x."
    LANG_MESSAGES["prompt_http_ports"]="Introduce los puertos HTTP (ej: 80,443,8080 o deja en blanco para predeterminados 80,443,8000,8080):"
    LANG_MESSAGES["invalid_port_format"]="[!] Formato de puerto inválido. Por favor, usa números separados por comas (ej: 80,443) o un rango (ej: 80-90) o deja en blanco."
    LANG_MESSAGES["prompt_ftp_ports"]="Introduce los puertos FTP (ej: 21 o deja en blanco para predeterminado 21):"
    LANG_MESSAGES["prompt_ssh_ports"]="Introduce los puertos SSH (ej: 22 o deja en blanco para predeterminado 22):"
    LANG_MESSAGES["prompt_custom_target"]="Introduce la IP o subred objetivo (ej: 192.168.1.1 o 192.168.1.0/24):"
    LANG_MESSAGES["invalid_target_format"]="[!] Formato de objetivo inválido. Por favor, introduce una IP o subred válida."
    LANG_MESSAGES["prompt_custom_nmap_args"]="Introduce argumentos personalizados de Nmap (ej: -p 22,80 -sV -A):"
    LANG_MESSAGES["generating_html_report"]="Generando informe HTML..."
    LANG_MESSAGES["no_xml_found"]="[!] No se encontraron archivos XML de Nmap en '$SCAN_SESSION_DIR'."
    LANG_MESSAGES["run_scan_first"]="Por favor, ejecute un escaneo primero."
    LANG_MESSAGES["xml_files_found"]="Archivos XML encontrados en '$SCAN_SESSION_DIR':"
    LANG_MESSAGES["generating_html_for"]="Generando HTML para '$xml_file_path' a '$output_html'"
    LANG_MESSAGES["html_generated_success"]="[✔] Informe HTML generado exitosamente: ${output_html}"
    LANG_MESSAGES["open_in_browser"]="Puede abrirlo en su navegador web."
    LANG_MESSAGES["html_generation_failed"]="[!] Falló la generación del informe HTML."
    LANG_MESSAGES["invalid_option_menu"]="Elige una opción" # Separate string for menu prompt
    LANG_MESSAGES["invalid_option_error"]="❌ Opción inválida" # Separate string for invalid option error
    LANG_MESSAGES["exiting_reports_saved"]="Saliendo. Los informes se guardan en $SCAN_SESSION_DIR"
    LANG_MESSAGES["exiting_message"]=":: Saliendo de AETHERIS. Hasta el próximo reconocimiento. ::"


    LANG_QUOTES=(
        "The stars are silent. Yet they watch."
        "In the dark, precision is your only ally."
        "Recon is not noise, it's poetry in silence."
        "What cannot be seen, cannot be stopped."
    )
    LANG_FOOTER=":: Desarrollado por AETHERIS // Operado por NyxKraken ::"

    LANG_ICON_PROMPTS["unicode_warning"]="⚠️ Tu terminal podría no soportar iconos Unicode."
    LANG_ICON_PROMPTS["install_nerdfont_prompt"]="¿Desea instalar una Nerd Font para mejores visuales? (y/n):"
    LANG_ICON_PROMPTS["download_nerdfont_link"]="👉 Descargue fuentes como FiraCode Nerd Font en:"
    LANG_ICON_PROMPTS["restart_terminal_tip"]="💡 Reinicie su terminal después de la instalación para aplicar los cambios."
}

# --- Functions ---

# Check for root privileges
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[!] Este script requiere privilegios de root para algunos escaneos de Nmap.${NC}"
        echo -e "${YELLOW}Por favor, ejecute con 'sudo bash aetheris.sh' o 'sudo ./aetheris.sh'.${NC}"
        exit 1
    fi
}

# Function to check for required tools
check_tool() {
    local tool=$1
    if ! command -v "$tool" &> /dev/null; then
        echo -e "${RED}${LANG_MESSAGES['tool_not_installed']}${NC}"
        echo -e "${YELLOW}${LANG_MESSAGES['install_tool']}${NC}"
        exit 1
    fi
    echo -e "${GREEN}${LANG_MESSAGES['tool_available']}${NC}"
}

# Function to clear screen and display banner
display_banner() {
    clear
    local random_quote="${LANG_QUOTES[$((RANDOM % ${#LANG_QUOTES[@]}))]}"

    echo -e "${BLUE}"
    echo "  █████╗ ███████╗████████╗██╗  ██╗███████╗██████╗ ██╗ ██████╗"
    echo " ██╔══██╗██╔════╝╚══██╔══╝██║  ██║██╔════╝██╔══██╗██║██╔════╝"
    echo " ███████║█████╗     ██║   ███████║█████╗  ██████╔╝██║█████╗  "
    echo " ██╔══██║██╔══╝     ██║   ██╔══██║██╔══╝  ██╔══██╗██║ ╔══╝██  "
    echo " ██║  ██║███████╗   ██║   ██║  ██║███████╗██║  ██║██║██████ ╗"
    echo " ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝╚══════╝"
    echo -e "${NC}"
    echo -e "${CYAN} ${LANG_MENU_TITLE}${NC}"
    echo -e "${MAGENTA}${random_quote}${NC}"
    echo -e "${YELLOW}${LANG_WARNING['ethical']}${NC}"
    echo
}

# Function to display the main menu
display_menu() {
    echo -e "${BLUE}:: Main Menu ::${NC}"
    echo -e "${GREEN}$(icon "🧠") 1) ${LANG_MENU_OPTIONS[0]}${NC}"
    echo -e "${GREEN}$(icon "🔭") 2) ${LANG_MENU_OPTIONS[1]}${NC}"
    echo -e "${GREEN}$(icon "🌐") 3) ${LANG_MENU_OPTIONS[2]}${NC}"
    echo -e "${GREEN}$(icon "🧭") 4) ${LANG_MENU_OPTIONS[3]}${NC}"
    echo -e "${GREEN}$(icon "🛠️") 5) ${LANG_MENU_OPTIONS[4]}${NC}"
    echo -e "${GREEN}$(icon "📂") 6) ${LANG_MENU_OPTIONS[5]}${NC}"
    echo -e "${GREEN}$(icon "🔐") 7) ${LANG_MENU_OPTIONS[6]}${NC}"
    echo -e "${GREEN}$(icon "⚙️") 8) ${LANG_MENU_OPTIONS[7]}${NC}"
    echo -e "${GREEN}$(icon "📄") 9) ${LANG_MENU_OPTIONS[8]}${NC}"
    echo -e "${RED}$(icon "❌") 10) ${LANG_MENU_OPTIONS[9]}${NC}"
    echo
    echo -n "$(icon "💡") ${YELLOW}${LANG_MESSAGES['invalid_option_menu']}: ${NC}"
}

# Function to get and validate target name
get_target_name() {
    read -rp "${YELLOW}${LANG_MESSAGES['prompt_target_name']} ${NC}" TARGET_NAME
    while [[ -z "$TARGET_NAME" || "$TARGET_NAME" =~ " " ]]; do
        echo -e "${RED}${LANG_MESSAGES['invalid_target_name']}${NC}"
        read -rp "${YELLOW}${LANG_MESSAGES['prompt_target_name']} ${NC}" TARGET_NAME
    done
}

# Function to get and validate IP address
get_ip_target() {
    local prompt_message="$1"
    read -rp "${YELLOW}${LANG_MESSAGES['prompt_ip_target']} ${prompt_message}: ${NC}" TARGET_IP
    while ! [[ "$TARGET_IP" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; do
        echo -e "${RED}${LANG_MESSAGES['invalid_ip_format']}${NC}"
        read -rp "${YELLOW}${LANG_MESSAGES['prompt_ip_target']} ${prompt_message}: ${NC}" TARGET_IP
    done
}

# Function to get and validate subnet
get_subnet_target() {
    local prompt_message="$1"
    read -rp "${YELLOW}${LANG_MESSAGES['prompt_subnet']} ${prompt_message}: ${NC}" TARGET_SUBNET
    while ! [[ "$TARGET_SUBNET" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$ ]]; do
        echo -e "${RED}${LANG_MESSAGES['invalid_subnet_format']}${NC}"
        read -rp "${YELLOW}${LANG_MESSAGES['prompt_subnet']} ${prompt_message}: ${NC}" TARGET_SUBNET
    done
}

# Function to get and validate ports
get_ports() {
    local prompt_message="$1"
    local default_ports="$2"
    read -rp "${YELLOW}${prompt_message} ${NC}" PORTS_INPUT
    if [[ -z "$PORTS_INPUT" ]]; then
        echo "Using default ports: $default_ports"
        PORTS_INPUT="$default_ports"
    else
        while ! [[ "$PORTS_INPUT" =~ ^([0-9]+(-[0-9]+)?)(,[0-9]+(-[0-9]+)?)*$ ]]; do
            echo -e "${RED}${LANG_MESSAGES['invalid_port_format']}${NC}"
            read -rp "${YELLOW}${prompt_message} ${NC}" PORTS_INPUT
            if [[ -z "$PORTS_INPUT" ]]; then # Allow blank for default if invalid input is given
                echo "Using default ports: $default_ports"
                PORTS_INPUT="$default_ports"
                break
            fi
        done
    fi
    echo "$PORTS_INPUT" # Return the validated ports
}


# Function to create session directory
create_session_dir() {
    SCAN_SESSION_DIR="aetheris_scans/${TARGET_NAME}_$(date +%Y%m%d_%H%M%S)"
    echo -e "${CYAN}${LANG_MESSAGES['reports_saved_to']} ${SCAN_SESSION_DIR}${NC}"
    mkdir -p "$SCAN_SESSION_DIR"
    if [[ $? -ne 0 ]]; then
        echo -e "${RED}${LANG_MESSAGES['failed_dir_creation']}${NC}"
        exit 1
    fi
}

# Function to run Nmap scan
run_nmap_scan() {
    local scan_name="$1"
    local nmap_args="$2"
    local target="$3"
    local output_file_base="${SCAN_SESSION_DIR}/${TARGET_NAME}_${scan_name}"

    echo -e "${BLUE}${LANG_MESSAGES['starting_nmap_scan']} ${target} (${scan_name})...${NC}"
    echo -e "${CYAN}${LANG_MESSAGES['command_to_execute']} nmap ${nmap_args} ${target} -oA ${output_file_base}${NC}"

    # Execute Nmap
    sudo nmap ${nmap_args} ${target} -oA "${output_file_base}"
    
    if [[ $? -eq 0 ]]; then
        echo -e "${GREEN}${LANG_MESSAGES['scan_completed_success']}${NC}"
        generate_summary "${output_file_base}.xml"
    else
        echo -e "${RED}${LANG_MESSAGES['scan_failed']}${NC}"
    fi
    echo -e "${BLUE}Press Enter to continue...${NC}"
    read -s
}

# Function to generate a quick summary from XML
generate_summary() {
    local xml_file="$1"
    echo -e "\n${BLUE}${LANG_MESSAGES['quick_summary']}${NC}"

    if [[ -f "$xml_file" ]]; then
        local active_hosts=$(grep -c '<status state="up"' "$xml_file")
        echo -e "${CYAN}${LANG_MESSAGES['hosts_active']} ${active_hosts}${NC}"

        if [[ "$active_hosts" -gt 0 ]]; then
            echo -e "${GREEN}--- Ports and Services ---${NC}"
            # Extract hosts, ports, and services using awk and xmlstarlet
            # Use 'xmlstarlet' for robust XML parsing. If not installed, fall back to grep/awk.
            if command -v xmlstarlet &> /dev/null; then
                xmlstarlet sel -t -m "//host" -v "address[@addrtype='ipv4']/@addr" -o " " -v "hostnames/hostname/@name" -n \
                -m "ports/port" -v "portid" -o "/" -v "protocol" -o " " -v "state/@state" -o " " -v "service/@name" -o " " -v "service/@product" -o " " -v "service/@version" -n "$xml_file" | \
                awk '
                {
                    ip = $1
                    hostname = $2
                    port = $3
                    state = $4
                    service = $5
                    product = $6
                    version = $7
                    
                    if (NR % 2 != 0) { # Process host line
                        current_ip = ip
                        current_hostname = hostname
                    } else { # Process port line
                        printf "  '"${CYAN}"'%s: %s'"${NC}"'\n", "'"${LANG_MESSAGES['host']}"'", current_ip
                        if (current_hostname != "") {
                            printf "  '"${CYAN}"'Hostname: %s'"${NC}"'\n", current_hostname
                        }
                        printf "    '"${MAGENTA}"'%s: %s/%s %s %s %s %s'"${NC}"'\n", "'"${LANG_MESSAGES['port']}"'", port, $4, $5, $6, $7, $8
                    }
                }'
            else
                echo -e "${YELLOW}Warning: xmlstarlet not found. Falling back to simpler grep/awk parsing. Consider installing xmlstarlet for more detailed summaries.${NC}"
                grep -E '(<address addrtype="ipv4" addr="[^"]+"|service name="[^"]+"|portid="[^"]+"|state="[^"]+")' "$xml_file" | \
                awk -F'[ ="]+' '
                /address addrtype="ipv4"/ {
                    ip = $5
                    print "  '"${CYAN}"''"${LANG_MESSAGES['host']}"': " ip "'"${NC}"'"
                }
                /portid=/ {
                    port = $2
                    protocol = $4
                    state = $6
                    service = ""
                    product = ""
                    version = ""
                    # Check for service details on the same line or subsequent lines
                    for (i = 7; i <= NF; i++) {
                        if ($i == "name") service = $(i+1)
                        else if ($i == "product") product = $(i+1)
                        else if ($i == "version") version = $(i+1)
                    }
                    printf "    '"${MAGENTA}"''"${LANG_MESSAGES['port']}"': %s/%s %s", port, protocol, state
                    if (service != "") printf " %s", service
                    if (product != "") printf " %s", product
                    if (version != "") printf " (%s)", version
                    print "'"${NC}"'"
                }'
            fi
        fi
    else
        echo -e "${RED}${LANG_MESSAGES['xml_file_not_found']} ${xml_file}${NC}"
    fi
}


# --- Scan Functions ---

# Option 1: Full reconnaissance (top 1000 ports, OS & service detection)
scan_full_reconnaissance() {
    get_target_name
    create_session_dir
    get_ip_target "for full reconnaissance"
    run_nmap_scan "full_recon" "-sC -sV -O --top-ports 1000" "$TARGET_IP"
}

# Option 2: Exhaustive scan (all 65535 ports, OS & service detection)
scan_exhaustive() {
    get_target_name
    create_session_dir
    get_ip_target "for exhaustive scan"
    echo -e "${YELLOW}${LANG_MESSAGES['starting_exhaustive_scan']}${NC}"
    run_nmap_scan "exhaustive" "-sC -sV -O -p-" "$TARGET_IP"
}

# Option 3: Local subnet host discovery
scan_local_subnet_discovery() {
    echo -e "${YELLOW}${LANG_MESSAGES['discovering_local_hosts']}${NC}"
    get_subnet_target "${LANG_MESSAGES['prompt_local_subnet_discovery']}"
    get_target_name # Get a name for the report
    create_session_dir # Create session directory for the report
    local output_file_base="${SCAN_SESSION_DIR}/${TARGET_NAME}_local_host_discovery"

    echo -e "${BLUE}${LANG_MESSAGES['executing_nmap_discovery']}${NC}"
    sudo nmap -sn "$TARGET_SUBNET" -oA "${output_file_base}"
    
    if [[ $? -eq 0 ]]; then
        echo -e "${GREEN}${LANG_MESSAGES['host_discovery_complete']}${NC}"
        echo -e "${CYAN}${LANG_MESSAGES['hosts_found']}${NC}"
        # Parse XML to find active hosts
        if [[ -f "${output_file_base}.xml" ]]; then
            grep '<address addrtype="ipv4"' "${output_file_base}.xml" | awk -F'"' '{print "  - " $4}'
        else
            echo -e "${RED}${LANG_MESSAGES['xml_file_not_found']} ${output_file_base}.xml${NC}"
        fi
        echo -e "${YELLOW}${LANG_MESSAGES['use_these_ips']}${NC}"
    else
        echo -e "${RED}${LANG_MESSAGES['host_discovery_failed']}${NC}"
    fi
    echo -e "${BLUE}Press Enter to continue...${NC}"
    read -s
}

# Option 4: SMB enumeration
scan_smb_enumeration() {
    get_target_name
    create_session_dir
    get_ip_target "for SMB enumeration"
    run_nmap_scan "smb_enum" "-p 445 --script smb-enum-shares,smb-enum-users,smb-os-discovery" "$TARGET_IP"
}

# Option 5: HTTP vulnerability scan (basic scripts)
scan_http_vuln() {
    get_target_name
    create_session_dir
    get_ip_target "for HTTP vulnerability scan"
    local default_http_ports="80,443,8000,8080"
    local ports=$(get_ports "${LANG_MESSAGES['prompt_http_ports']}" "$default_http_ports")
    run_nmap_scan "http_vuln" "-p ${ports} --script http-enum,http-headers,http-vuln-cve2017-1001000" "$TARGET_IP"
}

# Option 6: FTP vulnerability scan (basic scripts)
scan_ftp_vuln() {
    get_target_name
    create_session_dir
    get_ip_target "for FTP vulnerability scan"
    local default_ftp_ports="21"
    local ports=$(get_ports "${LANG_MESSAGES['prompt_ftp_ports']}" "$default_ftp_ports")
    run_nmap_scan "ftp_vuln" "-p ${ports} --script ftp-anon,ftp-bounce" "$TARGET_IP"
}

# Option 7: SSH enumeration (basic scripts)
scan_ssh_enum() {
    get_target_name
    create_session_dir
    get_ip_target "for SSH enumeration"
    local default_ssh_ports="22"
    local ports=$(get_ports "${LANG_MESSAGES['prompt_ssh_ports']}" "$default_ssh_ports")
    run_nmap_scan "ssh_enum" "-p ${ports} --script ssh-hostkey,ssh-auth-methods" "$TARGET_IP"
}

# Option 8: Custom Nmap Scan (Advanced)
scan_custom_nmap() {
    get_target_name
    create_session_dir
    local custom_target
    read -rp "${YELLOW}${LANG_MESSAGES['prompt_custom_target']} ${NC}" custom_target
    while ! [[ "$custom_target" =~ ^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(/[0-9]{1,2})?)$ ]]; do
        echo -e "${RED}${LANG_MESSAGES['invalid_target_format']}${NC}"
        read -rp "${YELLOW}${LANG_MESSAGES['prompt_custom_target']} ${NC}" custom_target
    done

    local custom_args
    read -rp "${YELLOW}${LANG_MESSAGES['prompt_custom_nmap_args']} ${NC}" custom_args
    
    run_nmap_scan "custom_scan" "${custom_args}" "$custom_target"
}

# Option 9: Generate HTML Report from XML
generate_html_report() {
    echo -e "${BLUE}${LANG_MESSAGES['generating_html_report']}${NC}"
    local scan_dirs=(aetheris_scans/*/) # Get all session directories
    
    if [[ ${#scan_dirs[@]} -eq 0 || ! -d "${scan_dirs[0]}" ]]; then
        echo -e "${YELLOW}${LANG_MESSAGES['no_xml_found']}${NC}"
        echo -e "${YELLOW}${LANG_MESSAGES['run_scan_first']}${NC}"
        echo -e "${BLUE}Press Enter to continue...${NC}"
        read -s
        return
    fi

    # Find all .xml files within aetheris_scans and its subdirectories
    mapfile -t xml_files < <(find aetheris_scans -name "*.xml" | sort)

    if [[ ${#xml_files[@]} -eq 0 ]]; then
        echo -e "${YELLOW}${LANG_MESSAGES['no_xml_found']}${NC}"
        echo -e "${YELLOW}${LANG_MESSAGES['run_scan_first']}${NC}"
    else
        echo -e "${CYAN}${LANG_MESSAGES['xml_files_found']}${NC}"
        select xml_file_path in "${xml_files[@]}"; do
            if [[ -n "$xml_file_path" ]]; then
                output_html="${xml_file_path%.xml}.html"
                echo -e "${GREEN}${LANG_MESSAGES['generating_html_for']}${NC}"
                xsltproc "$xml_file_path" -o "$output_html"
                if [[ $? -eq 0 ]]; then
                    echo -e "${GREEN}${LANG_MESSAGES['html_generated_success']}${NC}"
                    echo -e "${CYAN}${LANG_MESSAGES['open_in_browser']}${NC}"
                else
                    echo -e "${RED}${LANG_MESSAGES['html_generation_failed']}${NC}"
                fi
                break
            else
                echo -e "${RED}${LANG_MESSAGES['invalid_option_error']}${NC}"
            fi
        done
    fi
    echo -e "${BLUE}Press Enter to continue...${NC}"
    read -s
}

# --- Main Logic ---
main() {
    clear # Clear screen at the very beginning
    
    # Determine language
    local choice_lang
    echo -e "${BLUE}Select Language / Selecciona Idioma:${NC}"
    echo -e "${GREEN}1) English${NC}"
    echo -e "${GREEN}2) Español${NC}"
    read -rp "$(icon "💡") Choose language (1/2): " choice_lang
    case "$choice_lang" in
        1) load_english_lang ;;
        2) load_spanish_lang ;;
        *)
            echo -e "${YELLOW}Invalid choice. Defaulting to English.${NC}"
            load_english_lang
            ;;
    esac

    # Initial check for icon support and Nerd Font prompt
    if [ "$USE_ICONS" = false ]; then
        echo -e "${YELLOW}${LANG_ICON_PROMPTS['unicode_warning']}${NC}"
        read -rp "${YELLOW}${LANG_ICON_PROMPTS['install_nerdfont_prompt']} ${NC}" install_nerdfont_choice
        if [[ "$install_nerdfont_choice" =~ ^[Yy]$ ]]; then
            echo -e "${CYAN}${LANG_ICON_PROMPTS['download_nerdfont_link']} ${BLUE}https://www.nerdfonts.com/font-downloads${NC}"
            echo -e "${YELLOW}${LANG_ICON_PROMPTS['restart_terminal_tip']}${NC}"
        fi
    fi
    echo

    # Debug: Confirm script started
    echo -e "🧪 Debug: AETHERIS started"

    check_root
    check_tool "nmap"
    check_tool "xsltproc" # For HTML report generation

    while true; do
        display_banner
        display_menu
        read -rp "$(icon "💡") ${LANG_MESSAGES['invalid_option_menu']}: " choice
        echo

        case $choice in
            1) scan_full_reconnaissance ;;
            2) scan_exhaustive ;;
            3) scan_local_subnet_discovery ;;
            4) scan_smb_enumeration ;;
            5) scan_http_vuln ;;
            6) scan_ftp_vuln ;;
            7) scan_ssh_enum ;;
            8) scan_custom_nmap ;;
            9) generate_html_report ;;
            10) # Exit
                echo -e "${YELLOW}${LANG_MESSAGES['exiting_reports_saved']}${NC}"
                echo -e "${CYAN}${LANG_MESSAGES['exiting_message']}${NC}"
                echo -e "${BLUE}${LANG_FOOTER}${NC}"
                break
                ;;
            *)\
                echo -e "${RED}${LANG_MESSAGES['invalid_option_error']}${NC}"
                echo -e "${BLUE}Press Enter to continue...${NC}"
                read -s
                ;;
        esac
    done
}

# Run the main function
main
