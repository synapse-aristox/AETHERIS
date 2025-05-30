#!/bin/bash

# ==============================
# AETHERIS ▸ Network Scanner
# Minimalist | Ethical | Precise
# ==============================

# ANSI Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# --- Language Configuration ---
# Declare associative arrays for translations
declare -A LANG_WARNING
declare -A LANG_MENU_TITLE
declare -A LANG_MENU_OPTIONS
declare -A LANG_MESSAGES
declare -A LANG_QUOTES
declare -A LANG_FOOTER

# Function to load English texts
load_english_lang() {
    LANG_WARNING["ethical"]="[!] WARNING: Unauthorized scanning may be illegal. Use responsibly."
    LANG_MENU_TITLE=":: AETHERIS ▸ Reconnaissance. Elegantly Executed ::"
    LANG_MENU_OPTIONS=(
        "🔍 Full reconnaissance (top 1000 ports, OS & service detection)"
        "🔭 Exhaustive scan (all 65535 ports, OS & service detection)"
        "🌐 Local subnet host discovery"
        "🧭 SMB enumeration"
        "🛠️ HTTP vulnerability scan (basic scripts)"
        "📂 FTP vulnerability scan (basic scripts)"
        "🔐 SSH enumeration (basic scripts)"
        "⚙️ Custom Nmap Scan (Advanced)"
        "📄 Generate HTML Report from XML"
        "❌ Exit"
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

    LANG_QUOTES=(
        "The stars are silent. Yet they watch."
        "In the dark, precision is your only ally."
        "Recon is not noise, it's poetry in silence."
        "What cannot be seen, cannot be stopped."
    )
    LANG_FOOTER=":: Powered by AETHERIS // Operated by NyxKraken ::"
}

# Function to load Spanish texts
load_spanish_lang() {
    LANG_WARNING["ethical"]="[!] ADVERTENCIA: El escaneo no autorizado puede ser ilegal. Use con responsabilidad."
    LANG_MENU_TITLE=":: AETHERIS ▸ Reconocimiento. Ejecución Elegante ::"
    LANG_MENU_OPTIONS=(
        "🔍 Reconocimiento completo (top 1000 puertos, detección de SO y servicios)"
        "🔭 Escaneo exhaustivo (todos los 65535 puertos, detección de SO y servicios)"
        "🌐 Descubrimiento de hosts en subred local"
        "🧭 Enumeración SMB"
        "🛠️ Escaneo de vulnerabilidades HTTP (scripts básicos)"
        "📂 Escaneo de vulnerabilidades FTP (scripts básicos)"
        "Enumeración SSH (scripts básicos)"
        "⚙️ Escaneo Nmap Personalizado (Avanzado)"
        "📄 Generar Informe HTML desde XML"
        "❌ Salir"
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

    LANG_QUOTES=(
        "The stars are silent. Yet they watch."
        "In the dark, precision is your only ally."
        "Recon is not noise, it's poetry in silence."
        "What cannot be seen, cannot be stopped."
    )
    LANG_FOOTER=":: Desarrollado por AETHERIS // Operado por NyxKraken ::"
}

# --- Functions ---

# Check for root privileges
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[!] ${LANG_MESSAGES['tool_not_installed']/.*/Este script requiere privilegios de root para algunos escaneos de Nmap.}${NC}" # Specific message for root
        echo -e "${YELLOW}${LANG_MESSAGES['install_tool']/.*/Por favor, ejecute con 'sudo bash aetheris.sh' o 'sudo ./aetheris.sh'.}${NC}" # Specific message for root
        exit 1
    fi
}

# Validate IP address format
validate_ip() {
    local ip=$1
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        IFS='.' read -r -a octets <<< "$ip"
        for octet in "${octets[@]}"; do
            [[ $octet -lt 0 || $octet -gt 255 ]] && return 1
        done
        return 0
    else
        return 1
    fi
}

# Validate subnet format
validate_subnet() {
    local subnet=$1
    if [[ $subnet =~ ^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/([0-9]{1,2})$ ]]; then
        local ip_part=${BASH_REMATCH[1]}
        local cidr_part=${BASH_REMATCH[2]}
        if validate_ip "$ip_part" && [[ $cidr_part -ge 0 && $cidr_part -le 32 ]]; then
            return 0
        else
            return 1
        fi
    else
        return 1
    fi
}

# Validate port format (single, range, or comma-separated)
validate_ports() {
    local ports=$1
    if [[ -z "$ports" ]]; then
        return 0
    fi
    if [[ $ports =~ ^([0-9]{1,5}(-[0-9]{1,5})?)(,([0-9]{1,5}(-[0-9]{1,5})?))*$ ]]; then
        IFS=',' read -r -a port_entries <<< "$ports"
        for entry in "${port_entries[@]}"; do
            if [[ $entry =~ ^([0-9]{1,5})-([0-9]{1,5})$ ]]; then
                local start_port=${BASH_REMATCH[1]}
                local end_port=${BASH_REMATCH[2]}
                if [[ $start_port -lt 1 || $start_port -gt 65535 || \
                      $end_port -lt 1 || $end_port -gt 65535 || \
                      $start_port -gt $end_port ]]; then
                    return 1
                fi
            elif [[ $entry =~ ^[0-9]{1,5}$ ]]; then
                local port=$entry
                [[ $port -lt 1 || $port -gt 65535 ]] && return 1
            else
                return 1
            fi
        done
        return 0
    else
        return 1
    fi
}

# Execute Nmap scan and check exit code
run_nmap_scan() {
    local scan_name_key=$1 # Now it's a key to LANG_MENU_OPTIONS
    shift # Remove scan_name_key from arguments
    local cmd=("$@")
    local output_file_prefix="${cmd[@]: -2:1}" # Get the -oA argument value

    echo -e "${YELLOW}${LANG_MESSAGES['starting_nmap_scan']} '${scan_name_key}'...${NC}"
    echo -e "${CYAN}${LANG_MESSAGES['command_to_execute']} ${cmd[*]}${NC}"
    
    "${cmd[@]}"

    if [[ $? -eq 0 ]]; then
        echo -e "${GREEN}${LANG_MESSAGES['scan_completed_success']//'$scan_name'/${scan_name_key}}${NC}" # Use parameter expansion for dynamic string
        local xml_output="${output_file_prefix}.xml"
        if [[ -f "$xml_output" ]]; then
            echo -e "${MAGENTA}${LANG_MESSAGES['quick_summary']}${NC}"
            local hosts_up=$(grep -c "host starttime" "$xml_output")
            echo -e "${MAGENTA}${LANG_MESSAGES['hosts_active']} ${hosts_up}${NC}"
            if [[ "$hosts_up" -gt 0 ]]; then
                grep -E '<address addr="[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"' "$xml_output" | while read -r line; do
                    local ip=$(echo "$line" | grep -oP 'addr="\K[^"]+')
                    local hostname=$(grep -A 10 "<address addr=\"$ip\"" "$xml_output" | grep -oP '<hostname name="\K[^"]+' | head -n 1)
                    
                    echo -e "${CYAN}${LANG_MESSAGES['host']} ${ip} ${NC}$( [[ -n "$hostname" ]] && echo "(${hostname})" )"
                    grep -A 10 "<address addr=\"$ip\"" "$xml_output" | grep -E '<port protocol="tcp" portid="[0-9]+">' | while read -r port_line; do
                        local port=$(echo "$port_line" | grep -oP 'portid="\K[^"]+')
                        local service=$(echo "$port_line" | grep -oP 'service name="\K[^"]+"')
                        local state=$(echo "$port_line" | grep -oP 'state state="\K[^"]+"')
                        if [[ "$state" == "open" ]]; then
                            echo -e "    ${GREEN}${LANG_MESSAGES['port']} $port/${NC}tcp (${service:-${LANG_MESSAGES['unknown']}})"
                        fi
                    done
                done
            fi
            echo -e "${MAGENTA}----------------------${NC}"
        else
            echo -e "${YELLOW}${LANG_MESSAGES['xml_file_not_found']} $xml_output${NC}"
        fi
    else
        echo -e "${RED}${LANG_MESSAGES['scan_failed']}${NC}"
    fi
}

# --- Main Script ---

# ASCII Logo (always in English as part of the brand)
echo -e "${BLUE}"
echo "+-+-+-+-+-+-+-+-+-+"
echo "|A|E|T|H|E|R|I|S|"
echo "+-+-+-+-+-+-+-+-+-+"
echo ":: Reconnaissance. Elegantly Executed ::"
echo ":: Powered by AETHERIS // Operated by NyxKraken ::" # This line is fixed to English
echo ""
echo -e "${NC}"

# Choose language
echo -e "${BLUE}──────────────────────────────────────────────${NC}"
echo -e "${CYAN}:: AETHERIS :: Language Selection / Selección de Idioma ::${NC}"
echo -e "${BLUE}──────────────────────────────────────────────${NC}"
echo "1) English"
echo "2) Español"
while true; do
    read -p "Choose your language / Elige tu idioma [1-2]: " lang_choice
    case $lang_choice in
        1) load_english_lang; break ;;
        2) load_spanish_lang; break ;;
        *) echo -e "${RED}Invalid choice / Opción inválida. Please enter 1 or 2.${NC}" ;;
    esac
done
echo "" # Empty line for better spacing

# Ethical Warning
echo -e "${RED}${LANG_WARNING['ethical']}${NC}\n"

# Check for root privileges
check_root

# Verify necessary tools
REQUIRED_TOOLS=(nmap xsltproc)
for tool in "${REQUIRED_TOOLS[@]}"; do
    if ! command -v "$tool" &> /dev/null; then
        echo -e "${RED}${LANG_MESSAGES['tool_not_installed']}${NC}"
        echo -e "${YELLOW}${LANG_MESSAGES['install_tool']}${NC}"
        exit 1
    fi
    echo -e "${GREEN}${LANG_MESSAGES['tool_available']}${NC}"
done

# Get target machine name and create session directory
while true; do
    read -p "${LANG_MESSAGES['prompt_target_name']} " TARGET_NAME
    if [[ -n "$TARGET_NAME" && ! "$TARGET_NAME" =~ " " ]]; then
        break
    else
        echo -e "${RED}${LANG_MESSAGES['invalid_target_name']}${NC}"
    fi
done

TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
SCAN_SESSION_DIR="${TARGET_NAME}_scans/${TIMESTAMP}"
mkdir -p "$SCAN_SESSION_DIR" || { echo -e "${RED}${LANG_MESSAGES['failed_dir_creation']}${NC}"; exit 1; }
echo -e "${GREEN}${LANG_MESSAGES['reports_saved_to']} $SCAN_SESSION_DIR${NC}"

# Main Menu
while true; do
    echo -e "\n${BLUE}──────────────────────────────────────────────${NC}"
    echo -e "${CYAN}${LANG_MENU_TITLE}${NC}"
    echo "1) ${LANG_MENU_OPTIONS[0]}"
    echo "2) ${LANG_MENU_OPTIONS[1]}"
    echo "3) ${LANG_MENU_OPTIONS[2]}"
    echo "4) ${LANG_MENU_OPTIONS[3]}"
    echo "5) ${LANG_MENU_OPTIONS[4]}"
    echo "6) ${LANG_MENU_OPTIONS[5]}"
    echo "7) ${LANG_MENU_OPTIONS[6]}"
    echo "8) ${LANG_MENU_OPTIONS[7]}"
    echo "9) ${LANG_MENU_OPTIONS[8]}"
    echo "10) ${LANG_MENU_OPTIONS[9]}"
    read -p "${LANG_MESSAGES['invalid_option_menu']} [1-10]: " opcion

    case $opcion in
    1) # Full reconnaissance
        read -p "${LANG_MESSAGES['prompt_subnet']} " TARGET_SUBNET
        if ! validate_subnet "$TARGET_SUBNET"; then
            echo -e "${RED}${LANG_MESSAGES['invalid_subnet_format']}${NC}"
            continue
        fi
        run_nmap_scan "${LANG_MENU_OPTIONS[0]}" nmap -sS -sV -sC -T4 --open -n -Pn --top-ports 1000 -O -oA "$SCAN_SESSION_DIR/recon_full_top1000" "$TARGET_SUBNET"
        ;;
    2) # Exhaustive scan
        read -p "${LANG_MESSAGES['prompt_subnet']} " TARGET_SUBNET
        if ! validate_subnet "$TARGET_SUBNET"; then
            echo -e "${RED}${LANG_MESSAGES['invalid_subnet_format']}${NC}"
            continue
        fi
        echo -e "${YELLOW}${LANG_MESSAGES['starting_exhaustive_scan']}${NC}"
        run_nmap_scan "${LANG_MENU_OPTIONS[1]}" nmap -sS -sV -sC -T4 --open -n -Pn -p- -O -oA "$SCAN_SESSION_DIR/recon_exhaustive_allports" "$TARGET_SUBNET"
        ;;
    3) # Local host discovery
        echo -e "${YELLOW}${LANG_MESSAGES['discovering_local_hosts']}${NC}"
        read -p "${LANG_MESSAGES['prompt_local_subnet_discovery']} " LOCAL_SUBNET_DISCOVERY
        if ! validate_subnet "$LOCAL_SUBNET_DISCOVERY"; then
            echo -e "${RED}${LANG_MESSAGES['invalid_subnet_format']}${NC}"
            continue
        fi
        echo -e "${YELLOW}${LANG_MESSAGES['executing_nmap_discovery']}${NC}"
        nmap -sn "$LOCAL_SUBNET_DISCOVERY" -oA "$SCAN_SESSION_DIR/host_discovery"
        if [[ $? -eq 0 ]]; then
            echo -e "${GREEN}${LANG_MESSAGES['host_discovery_complete']}${NC}"
            echo -e "${CYAN}${LANG_MESSAGES['hosts_found']}${NC}"
            grep "Nmap scan report for" "$SCAN_SESSION_DIR/host_discovery.nmap" | awk '{print $5}'
            echo -e "${GREEN}${LANG_MESSAGES['use_these_ips']}${NC}"
        else
            echo -e "${RED}${LANG_MESSAGES['host_discovery_failed']}${NC}"
        fi
        ;;
    4) # SMB enumeration
        read -p "${LANG_MESSAGES['prompt_ip_target']} SMB: " TARGET_IP
        if ! validate_ip "$TARGET_IP"; then
            echo -e "${RED}${LANG_MESSAGES['invalid_ip_format']}${NC}"
            continue
        fi
        run_nmap_scan "${LANG_MENU_OPTIONS[3]}" nmap -p 139,445 --script smb-enum-shares,smb-enum-users,smb-os-discovery,smb-brute -oA "$SCAN_SESSION_DIR/smb_enum_$TARGET_IP" "$TARGET_IP"
        ;;
    5) # HTTP vulnerability scan
        read -p "${LANG_MESSAGES['prompt_ip_target']} HTTP: " TARGET_IP
        if ! validate_ip "$TARGET_IP"; then
            echo -e "${RED}${LANG_MESSAGES['invalid_ip_format']}${NC}"
            continue
        fi
        read -p "${LANG_MESSAGES['prompt_http_ports']} " HTTP_PORTS_INPUT
        if [[ -z "$HTTP_PORTS_INPUT" ]]; then
            HTTP_PORTS="80,443,8000,8080"
        elif ! validate_ports "$HTTP_PORTS_INPUT"; then
            echo -e "${RED}${LANG_MESSAGES['invalid_port_format']}${NC}"
            continue
        else
            HTTP_PORTS="$HTTP_PORTS_INPUT"
        fi
        run_nmap_scan "${LANG_MENU_OPTIONS[4]}" nmap -p "$HTTP_PORTS" --script http-vuln-*,http-title,http-headers,http-enum,http-methods -oA "$SCAN_SESSION_DIR/http_vulns_$TARGET_IP" "$TARGET_IP"
        ;;
    6) # FTP vulnerability scan
        read -p "${LANG_MESSAGES['prompt_ip_target']} FTP: " TARGET_IP
        if ! validate_ip "$TARGET_IP"; then
            echo -e "${RED}${LANG_MESSAGES['invalid_ip_format']}${NC}"
            continue
        fi
        read -p "${LANG_MESSAGES['prompt_ftp_ports']} " FTP_PORTS_INPUT
        if [[ -z "$FTP_PORTS_INPUT" ]]; then
            FTP_PORTS="21"
        elif ! validate_ports "$FTP_PORTS_INPUT"; then
            echo -e "${RED}${LANG_MESSAGES['invalid_port_format']}${NC}"
            continue
        else
            FTP_PORTS="$FTP_PORTS_INPUT"
        fi
        run_nmap_scan "${LANG_MENU_OPTIONS[5]}" nmap -p "$FTP_PORTS" --script ftp-anon,ftp-vsftpd-backdoor,ftp-bounce -oA "$SCAN_SESSION_DIR/ftp_vulns_$TARGET_IP" "$TARGET_IP"
        ;;
    7) # SSH enumeration
        read -p "${LANG_MESSAGES['prompt_ip_target']} SSH: " TARGET_IP
        if ! validate_ip "$TARGET_IP"; then
            echo -e "${RED}${LANG_MESSAGES['invalid_ip_format']}${NC}"
            continue
        fi
        read -p "${LANG_MESSAGES['prompt_ssh_ports']} " SSH_PORTS_INPUT
        if [[ -z "$SSH_PORTS_INPUT" ]]; then
            SSH_PORTS="22"
        elif ! validate_ports "$SSH_PORTS_INPUT"; then
            echo -e "${RED}${LANG_MESSAGES['invalid_port_format']}${NC}"
            continue
        else
            SSH_PORTS="$SSH_PORTS_INPUT"
        fi
        run_nmap_scan "${LANG_MENU_OPTIONS[6]}" nmap -p "$SSH_PORTS" --script sshv1,ssh-hostkey,ssh-brute,ssh-publickey-accept -oA "$SCAN_SESSION_DIR/ssh_enum_$TARGET_IP" "$TARGET_IP"
        ;;
    8) # Custom Nmap Scan
        read -p "${LANG_MESSAGES['prompt_custom_target']} " CUSTOM_TARGET
        if ! (validate_ip "$CUSTOM_TARGET" || validate_subnet "$CUSTOM_TARGET"); then
            echo -e "${RED}${LANG_MESSAGES['invalid_target_format']}${NC}"
            continue
        fi
        read -p "${LANG_MESSAGES['prompt_custom_nmap_args']} " CUSTOM_NMAP_ARGS
        if [[ ! "$CUSTOM_NMAP_ARGS" =~ -v ]]; then
            CUSTOM_NMAP_ARGS="$CUSTOM_NMAP_ARGS -v"
        fi
        run_nmap_scan "${LANG_MENU_OPTIONS[7]}" nmap $CUSTOM_NMAP_ARGS -oA "$SCAN_SESSION_DIR/custom_scan_$(echo "$CUSTOM_TARGET" | tr -d '/' | tr '.' '_')" "$CUSTOM_TARGET"
        ;;
    9) # Generate HTML Report
        echo -e "${YELLOW}${LANG_MESSAGES['generating_html_report']}${NC}"
        xml_files=($(find "$SCAN_SESSION_DIR" -maxdepth 1 -name "*.xml"))
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
        ;;
    10) # Exit
        echo -e "${YELLOW}${LANG_MESSAGES['exiting_reports_saved']}${NC}"
        break
        ;;
    *)
        echo -e "${RED}${LANG_MESSAGES['invalid_option_error']}${NC}"
        ;;
    esac
done

# Footer
RANDOM_QUOTE=${LANG_QUOTES[$RANDOM % ${#LANG_QUOTES[@]}]}
echo -e "\n${CYAN}:: $RANDOM_QUOTE ::${NC}"
echo -e "${BLUE}${LANG_FOOTER}${NC}\n"