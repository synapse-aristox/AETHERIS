# aetheris_main.py (Este archivo está en la raíz de tu proyecto AETHERIS_FULL)

import os
import sys
import configparser
from datetime import datetime
import logging
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.box import MINIMAL_HEAVY

# --- INICIO: SOLUCIÓN PARA ERRORES DE IMPORTACIÓN ---
# Esta línea fuerza a Python a reconocer el directorio donde se encuentra este script
# (que es la raíz de tu proyecto 'AETHERIS_FULL') como una ubicación para buscar módulos.
# Esto ayuda a VS Code (Pylance) a resolver las importaciones correctamente
# y asegura que el script funcione bien sin importar desde dónde se ejecute.
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
# --- FIN: SOLUCIÓN PARA ERRORES DE IMPORTACIÓN ---


# Importar funciones y logger de lib/utils.py
# Usamos el punto inicial '.' porque 'lib' es una carpeta hermana a este script
# en el mismo nivel de paquete (la raíz AETHERIS_FULL).
from .lib.utils import (
    setup_logging, get_timestamp, ensure_directory,
    validate_ip, validate_subnet, extract_target_ip_from_path,
    aetheris_logger as logger, # Importa la instancia del logger ya configurada
    slugify, # Asegúrate de que slugify también esté en utils.py y lo importas aquí
    is_public_ip # <-- ¡IMPORTACIÓN DE LA NUEVA FUNCIÓN!
)

# Importar módulos de escaneo, parseo, análisis y reporte (todos dentro de 'lib/')
from .lib import nmap_scanner
from .lib import nmap_parser
from .lib import cve_matcher
from .lib import report_generator

# Estos módulos están directamente en la carpeta raíz 'AETHERIS_FULL'
from .analizar_vs_scan import mostrar_coincidencias
from .update_cves import actualizar_cves # <-- Asegúrate que tu archivo se llama 'update_cves.py'


# --- Configuración de Rich Console ---
console = Console()

# --- Rutas Globales ---
# BASE_DIR ahora apunta a la raíz del proyecto (AETHERIS_FULL)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Las rutas se construyen a partir de BASE_DIR
CONFIG_DIR = os.path.join(BASE_DIR, "config")
RESULTS_DIR = os.path.join(BASE_DIR, "results") # Ajustado a 'results' según tu estructura
CVE_DATA_DIR = os.path.join(BASE_DIR, "cve_data") # 'cve_data' es la carpeta padre
CVE_DATABASE_PATH = os.path.join(CVE_DATA_DIR, "cves_actuales.txt") # Ruta completa
CONFIG_FILE_PATH = os.path.join(CONFIG_DIR, "aetheris.conf")


# --- Funciones de Configuración ---
def create_default_config(config_path):
    """
    Crea un archivo de configuración por defecto si no existe.
    """
    config = configparser.ConfigParser()
    config['GLOBAL'] = {
        'results_directory': 'results', # Relativo a AETHERIS_FULL
        'cve_database_path': 'cve_data/cves_actuales.txt', # Relativo a AETHERIS_FULL
        'log_level': 'INFO', # DEBUG, INFO, WARNING, ERROR, CRITICAL
        'log_file_path': 'logs/aetheris.log' # Relativo a AETHERIS_FULL
    }
    config['NMAP'] = {
        'default_scan_options': '-sV -O -Pn --max-retries 2 --host-timeout 30m'
    }

    try:
        ensure_directory(os.path.dirname(config_path))
        with open(config_path, 'w', encoding='utf-8') as configfile:
            config.write(configfile)
        logger.info(f"Archivo de configuración por defecto creado en '{config_path}'")
        return config
    except Exception as e:
        logger.error(f"❌ Error al crear el archivo de configuración por defecto en '{config_path}': {e}")
        return configparser.ConfigParser() # Retorna una config vacía si falla


def load_config(config_path):
    """
    Carga el archivo de configuración principal de Aetheris.
    Si no existe, crea uno por defecto.
    """
    config = configparser.ConfigParser()
    if not os.path.isfile(config_path):
        logger.warning(f"⚠️ Archivo de configuración no encontrado en '{config_path}'. Creando uno por defecto.")
        return create_default_config(config_path)

    try:
        config.read(config_path, encoding="utf-8")
        logger.info(f"Archivo de configuración '{config_path}' cargado exitosamente.")
    except Exception as e:
        logger.error(f"❌ Error al leer configuración desde '{config_path}': {e}. Usando valores por defecto.")
        # Intentar crear un config por defecto si la lectura falla para evitar un crash
        config = create_default_config(config_path)
    return config


def display_menu(config):
    """
    Muestra el menú principal de Aetheris.
    """
    menu_options = [
        "1. Escaneo y Análisis Completo",
        "2. Actualizar Base de Datos de CVEs",
        "3. Mostrar Historial de Escaneos",
        "4. Configuración (próximamente)",
        "5. Salir"
    ]

    version_info = Text("Aetheris v0.3 Beta", style="bold green")
    welcome_text = Text("Bienvenido a Aetheris", style="bold cyan")

    panel_content = Table.grid(padding=1)
    panel_content.add_row(welcome_text)
    panel_content.add_row(Text("")) # Separador
    for option in menu_options:
        panel_content.add_row(Text(option, style="white"))
    panel_content.add_row(Text("")) # Separador
    panel_content.add_row(version_info)

    console.print(
        Panel(
            panel_content,
            title="[bold blue]Aetheris - Scanner de Vulnerabilidades[/bold blue]",
            title_align="center",
            border_style="blue",
            box=MINIMAL_HEAVY,
            padding=(1, 2)
        )
    )

def get_target_input():
    """
    Solicita al usuario la IP o rango CIDR a escanear y la valida.
    """
    while True:
        target = console.input("[bold green]Ingrese la IP o rango CIDR a escanear (ej. 192.168.1.1 o 192.168.1.0/24): [/bold green]").strip()
        if validate_ip(target) or validate_subnet(target):
            return target
        else:
            console.print("[red]❌ Entrada inválida. Por favor, ingrese una IP IPv4 o un rango CIDR IPv4 válido.[/red]")

# --- Funciones de Operación ---

def run_full_scan_and_analysis(config):
    """
    Orquesta el flujo completo de escaneo Nmap, parseo, correlación CVE y generación de reportes.
    """
    console.print(Panel("[bold yellow]Iniciando Escaneo y Análisis Completo...[/bold yellow]", border_style="yellow"))
    target = get_target_input()
    if not target:
        logger.warning("No se proporcionó un objetivo. Cancelando escaneo.")
        return

    # --- NUEVA LÓGICA DE ADVERTENCIA PARA IP PÚBLICA ---
    # Si el target es un rango CIDR, la función is_public_ip toma la IP base para verificar.
    if is_public_ip(target):
        console.print(Panel(
            f"[bold red]⚠️ ¡ADVERTENCIA: El objetivo '{target}' parece ser una IP pública![/bold red]\n"
            "Escanear IPs públicas sin permiso explícito es ilegal y poco ético.\n"
            "[yellow]¿Desea continuar con el escaneo de esta IP pública? (s/N)[/yellow]",
            border_style="red"
        ))
        confirmation = console.input("[bold yellow]Su elección: [/bold yellow]").strip().lower()
        if confirmation != 's':
            logger.info(f"Escaneo de IP pública '{target}' cancelado por el usuario.")
            console.print("[yellow]Escaneo cancelado.[/yellow]")
            return
        else:
            logger.warning(f"El usuario ha confirmado el escaneo de la IP pública: {target}")
            console.print("[bold green]Continuando con el escaneo de IP pública bajo su responsabilidad.[/bold green]")
    # --- FIN NUEVA LÓGICA DE ADVERTENCIA ---

    # --- 1. Preparar directorio de resultados ---
    timestamp = get_timestamp()
    target_slug = slugify(target) # Usar slugify para nombres de directorio seguros

    # Path de resultados: BASE_DIR + 'results' (del config) + target_slug_timestamp
    results_root_dir_name = config.get('GLOBAL', 'results_directory', fallback='results')
    current_results_dir = os.path.join(
        BASE_DIR,
        results_root_dir_name,
        f"{target_slug}_{timestamp}"
    )
    ensure_directory(current_results_dir)
    logger.info(f"Directorio de resultados creado: {current_results_dir}")

    # --- 2. Ejecutar escaneo Nmap ---
    console.print(f"\n[bold blue]🚀 Ejecutando Nmap para {target}...[/bold blue]")
    
    # Obtener las opciones de Nmap del archivo de configuración
    nmap_default_options = config.get('NMAP', 'default_scan_options', 
                                     fallback='-sV -O -Pn --max-retries 2 --host-timeout 30m')
    
    # PASA las opciones de Nmap a la función run_nmap_scan
    nmap_xml_path = nmap_scanner.run_nmap_scan(target, current_results_dir, nmap_default_options)

    if not nmap_xml_path or not os.path.exists(nmap_xml_path):
        logger.error(f"❌ Nmap no pudo completar el escaneo o no se generó el archivo XML válido para {target}.")
        console.print("[red]El escaneo Nmap falló o no produjo un archivo XML válido. Saliendo.[/red]")
        return

    # --- 3. Parsear el resultado XML de Nmap ---
    console.print("\n[bold blue]⚙️ Procesando resultados de Nmap...[/bold blue]")
    try:
        scanned_services = nmap_parser.parse_nmap_xml(nmap_xml_path)
        if not scanned_services:
            logger.warning(f"No se encontraron servicios válidos en el archivo XML de Nmap: {nmap_xml_path}")
            console.print("[yellow]No se encontraron servicios o puertos abiertos en el escaneo Nmap.[/yellow]")
            return
        logger.info(f"Servicios escaneados encontrados: {len(scanned_services)}")
        logger.debug(f"Servicios parseados: {scanned_services}")
    except Exception as e:
        logger.error(f"❌ Error al parsear el XML de Nmap '{nmap_xml_path}': {e}")
        console.print("[red]Ocurrió un error al procesar el XML de Nmap. Saliendo.[/red]")
        return

    # --- 4. Cargar la base de datos de CVEs ---
    console.print("\n[bold blue]📚 Cargando base de datos de CVEs...[/bold blue]")

    # Ruta de la base de datos de CVEs: BASE_DIR + 'cve_data/cves_actuales.txt' (del config)
    cve_db_path_from_config = config.get('GLOBAL', 'cve_database_path', fallback='cve_data/cves_actuales.txt')
    # Asegúrate de que la ruta sea absoluta relativa a BASE_DIR
    cve_db_path = os.path.join(BASE_DIR, cve_db_path_from_config)

    if not os.path.exists(cve_db_path) or os.path.getsize(cve_db_path) == 0:
        logger.warning(f"Base de datos de CVEs no encontrada o vacía en '{cve_db_path}'. Sugerencia: Actualícela desde el menú principal.")
        console.print("[yellow]⚠️ Base de datos de CVEs no encontrada o vacía. ¡Recomiendo actualizarla primero desde el menú principal![/yellow]")
        cves_db = {} # Continuar con una base de datos vacía
    else:
        try:
            cves_db = cve_matcher.load_cve_database(cve_db_path)
            logger.info(f"Base de datos de CVEs cargada con {len(cves_db)} entradas.")
        except Exception as e:
            logger.error(f"❌ Error al cargar la base de datos de CVEs desde '{cve_db_path}': {e}")
            console.print("[red]Ocurrió un error al cargar la base de datos de CVEs. Continuaré sin ella.[/red]")
            cves_db = {}

    # --- 5. Correlacionar CVEs con servicios escaneados ---
    console.print("\n[bold blue]🔍 Correlacionando CVEs con servicios escaneados...[/bold blue]")
    try:
        found_vulnerabilities = cve_matcher.match_cves_to_scan_results(scanned_services, cves_db)
        logger.info(f"Vulnerabilidades encontradas: {len(found_vulnerabilities)}")
    except Exception as e:
        logger.error(f"❌ Error al correlacionar CVEs: {e}")
        console.print("[red]Ocurrió un error al correlacionar CVEs. No se generará reporte de vulnerabilidades.[/red]")
        found_vulnerabilities = []

    # --- 6. Generar Reportes ---
    console.print("\n[bold blue]📄 Generando reportes...[/bold blue]")
    try:
        report_data = {
            "target": target,
            "timestamp": timestamp,
            "scanned_services": scanned_services,
            "found_vulnerabilities": found_vulnerabilities,
            "nmap_xml_path": nmap_xml_path
        }

        # Generar reporte TXT
        txt_report_path = os.path.join(current_results_dir, f"{target_slug}_{timestamp}_report.txt")
        report_generator.generate_txt_report(report_data, txt_report_path)
        logger.info(f"Reporte TXT generado: {txt_report_path}")

        # Generar reporte HTML
        html_report_path = os.path.join(current_results_dir, f"{target_slug}_{timestamp}_report.html")
        report_generator.generate_html_report(report_data, html_report_path)
        logger.info(f"Reporte HTML generado: {html_report_path}")

        console.print(Panel(
            f"[bold green]✔️ Escaneo y Análisis Completado para {target}![/bold green]\n"
            f"Resultados guardados en: [yellow]{current_results_dir}[/yellow]\n"
            f"Reporte TXT: [yellow]{txt_report_path}[/yellow]\n"
            f"Reporte HTML: [yellow]{html_report_path}[/yellow]",
            border_style="green"
        ))

        # Mostrar tabla de coincidencias si hay
        if found_vulnerabilities:
            console.print(Panel("[bold cyan]Resumen de Vulnerabilidades Encontradas:[/bold cyan]", border_style="cyan"))
            # Adaptamos mostrar_coincidencias para que tome los datos directamente
            # y el logger
            mostrar_coincidencias(found_vulnerabilities, logger)
        else:
            console.print(Panel("[bold green]🎉 ¡No se encontraron vulnerabilidades para los servicios detectados![/bold green]", border_style="green"))


    except Exception as e:
        logger.error(f"❌ Error al generar reportes: {e}")
        console.print("[red]Ocurrió un error al generar los reportes. Los resultados pueden estar incompletos.[/red]")


def update_cve_database_action(config):
    """
    Acción para actualizar la base de datos de CVEs.
    """
    console.print(Panel("[bold yellow]Iniciando actualización de la Base de Datos de CVEs...[/bold yellow]", border_style="yellow"))

    # Ruta de la base de datos de CVEs desde la configuración
    cve_db_path_from_config = config.get('GLOBAL', 'cve_database_path', fallback='cve_data/cves_actuales.txt')
    # Convertir a ruta absoluta usando BASE_DIR
    cve_db_path = os.path.join(BASE_DIR, cve_db_path_from_config)

    # Asegurarse de que el directorio cve_data exista
    ensure_directory(os.path.dirname(cve_db_path))

    # El módulo 'actualizar_cves' ya se importó al principio del script.
    try:
        actualizar_cves(cve_db_path)
        console.print(Panel(
            f"[bold green]✔️ Base de datos de CVEs actualizada exitosamente en '{cve_db_path}'![/bold green]",
            border_style="green"
        ))
        logger.info(f"Base de datos de CVEs actualizada exitosamente en '{cve_db_path}'.")
    except Exception as e:
        logger.error(f"❌ Error al actualizar la base de datos de CVEs: {e}")
        console.print(Panel(
            f"[bold red]❌ Falló la actualización de la base de datos de CVEs: {e}[/bold red]",
            border_style="red"
        ))

def show_scan_history_action(config):
    """
    Muestra un listado de los escaneos realizados previamente.
    """
    results_base_dir_name = config.get('GLOBAL', 'results_directory', fallback='results')
    full_results_path = os.path.join(BASE_DIR, results_base_dir_name)
    ensure_directory(full_results_path) # Asegurarse de que exista el directorio principal

    console.print(Panel("[bold cyan]Historial de Escaneos[/bold cyan]", border_style="cyan"))

    scan_dirs = []
    try:
        for entry in os.listdir(full_results_path):
            full_path = os.path.join(full_results_path, entry)
            # El patrón es "TARGET_TIMESTAMP"
            if os.path.isdir(full_path) and '_' in entry and len(entry.split('_')) > 1:
                # Intenta asegurar que el segundo split sea un timestamp válido antes de añadirlo
                try:
                    timestamp_part = entry.split("_", 1)[1]
                    datetime.strptime(timestamp_part, "%Y%m%d_%H%M%S") # Intenta parsear para validar
                    scan_dirs.append(full_path)
                except ValueError:
                    # No es un directorio de escaneo con timestamp, ignorar
                    pass

        scan_dirs.sort(key=os.path.getmtime, reverse=True) # Ordenar por fecha de modificación (más reciente primero)

        if not scan_dirs:
            console.print("[yellow]No se encontraron escaneos previos.[/yellow]")
            logger.info("No se encontró historial de escaneos.")
            return

        table = Table(
            title="Escaneos Anteriores",
            style="white",
            header_style="bold magenta",
            box=MINIMAL_HEAVY,
            show_lines=True
        )
        table.add_column("No.", style="dim")
        table.add_column("Objetivo (IP)", style="cyan")
        table.add_column("Fecha/Hora Escaneo", style="green")
        table.add_column("Ruta Resultados", style="blue")

        for i, scan_path in enumerate(scan_dirs):
            ip = extract_target_ip_from_path(scan_path) # Esta función ya extrae la IP
            # Obtener el timestamp directamente del nombre de la carpeta
            try:
                base_name = os.path.basename(scan_path)
                timestamp_str = base_name.split("_", 1)[1]
                dt_object = datetime.strptime(timestamp_str, "%Y%m%d_%H%M%S")
                formatted_dt = dt_object.strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                formatted_dt = "Desconocida"

            table.add_row(
                str(i + 1),
                ip,
                formatted_dt,
                scan_path
            )

        console.print(table)
        logger.info(f"Mostrado historial de {len(scan_dirs)} escaneos.")

    except Exception as e:
        logger.error(f"❌ Error al mostrar el historial de escaneos: {e}")
        console.print(f"[red]Ocurrió un error al cargar el historial: {e}[/red]")


def main():
    """
    Función principal de Aetheris.
    """
    # 1. Cargar configuración
    config = load_config(CONFIG_FILE_PATH)

    # 2. Configurar el logger principal de Aetheris
    log_level = config.get('GLOBAL', 'log_level', fallback='INFO')
    log_file_path_from_config = config.get('GLOBAL', 'log_file_path', fallback='logs/aetheris.log')

    # Asegúrate de que la ruta del log sea absoluta, basada en BASE_DIR
    log_file_path = os.path.join(BASE_DIR, log_file_path_from_config)

    # Esta llamada configura el logger importado 'logger'
    setup_logging(log_level=log_level, log_file_path=log_file_path)
    logger.info("Aetheris iniciado.")

    # Asegurarse de que el directorio base de resultados exista
    results_base_dir_name = config.get('GLOBAL', 'results_directory', fallback='results')
    ensure_directory(os.path.join(BASE_DIR, results_base_dir_name))

    # Asegurarse de que el directorio cve_data exista
    cve_data_path_from_config = config.get('GLOBAL', 'cve_database_path', fallback='cve_data/cves_actuales.txt')
    cve_data_dir = os.path.dirname(os.path.join(BASE_DIR, cve_data_path_from_config))
    ensure_directory(cve_data_dir)


    while True:
        display_menu(config)
        choice = console.input("[bold yellow]Seleccione una opción: [/bold yellow]").strip()

        if choice == '1':
            run_full_scan_and_analysis(config)
        elif choice == '2':
            update_cve_database_action(config)
        elif choice == '3':
            show_scan_history_action(config)
        elif choice == '4':
            console.print(Panel("[bold yellow]La configuración aún no está implementada.[/bold yellow]", border_style="yellow"))
        elif choice == '5':
            logger.info("Saliendo de Aetheris. ¡Hasta luego!")
            console.print(Panel("[bold green]¡Gracias por usar Aetheris! Saliendo...[/bold green]", border_style="green"))
            break
        else:
            console.print("[red]Opción inválida. Por favor, intente de nuevo.[/red]")

        console.input("\n[dim]Presione ENTER para continuar...[/dim]")
        os.system('cls' if os.name == 'nt' else 'clear') # Limpia la consola


if __name__ == "__main__":
    main()