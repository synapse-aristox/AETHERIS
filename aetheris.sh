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
        "Full reconnaissance (top 1000 ports, OS & service detection)" # Emojis REMOVED from definition
        "Exhaustive scan (all 65535 ports, OS & service detection)"    # Emojis REMOVED from definition
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
        "Reconocimiento completo (top 1000 puertos, detección de SO y servicios)" # Emojis REMOVED from definition
        "Escaneo exhaustivo (todos los 65535 puertos, detección de SO y servicios)"    # Emojis REMOVED from definition
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
    if [[ $EUID -ne 0 ]]; then # Esta es la línea 206 que debes verificar
        # Este mensaje es ahora localizado a través de LANG_MESSAGES['tool_not_installed'] y ['install_tool']
        echo -e "${RED}[!] Este script requiere privilegios de root para algunos escaneos de Nmap.${NC}" # Este parte del mensaje podría seguir estando hardcoded o usar una clave específica si es necesario
        echo -e "${YELLOW}Por favor, ejecute con 'sudo bash aetheris.sh' o 'sudo ./aetheris.sh'.${NC}" # Este parte del mensaje podría seguir estando hardcoded o usar una clave específica si es necesario
        exit 1
    fi
}
