# aetheris/actualizar_cves.py
import os
import requests
import datetime
import configparser # Importar configparser aquí también

# Se puede definir una función principal que tome la configuración
def update_cve_database(config):
    """
    Función para actualizar la base de datos de CVEs.
    Lee la configuración de 'config' para filtros.
    """
    console_temp = Console() # Usar una consola temporal para este script

    cve_file_path = "cves_actuales.txt"

    # Cargar configuración desde el objeto config pasado
    cve_updates_section = config.get('CVE_UPDATES', {}) # Get a dictionary-like section

    vulners_api_url = cve_updates_section.get('vulners_api_url', 'https://vulners.com/api/v3/search/lucene/')
    min_cvss_score = float(cve_updates_section.get('min_cvss_score', '7.0'))
    min_year = int(cve_updates_section.get('min_year', '2022'))
    enable_exploit_filter = cve_updates_section.get('enable_exploit_filter', 'yes').lower() == 'yes'
    enable_incremental = cve_updates_section.get('enable_incremental', 'yes').lower() == 'yes'
    vulners_api_key = cve_updates_section.get('vulners_api_key', 'YOUR_API_KEY_HERE') # Por si se necesita

    console_temp.print(f"\n[bold yellow]📡 Iniciando actualización de CVEs desde Vulners...[/bold yellow]")
    console_temp.print(f"Filtros: CVSS >= {min_cvss_score}, Año >= {min_year}, Exploit: {enable_exploit_filter}, Incremental: {enable_incremental}")

    # Aquí iría la lógica de actualización de CVEs
    # Asegúrarse de que esta lógica use los parámetros de 'config'
    # Ejemplo:
    # Consulta la API de Vulners, filtra por los parámetros, etc.
    # Por ahora, un placeholder:
    cves_data = [] # Esto se llenaría con datos reales de la API

    # Simulación de descarga y procesamiento (reemplazar con tu lógica real)
    try:
        # Ejemplo de cómo se podría cargar el contenido de cves_actuales.txt para incremental
        last_update_date = None
        if enable_incremental and os.path.exists(cve_file_path):
            with open(cve_file_path, 'r', encoding='utf-8') as f:
                first_line = f.readline()
                if first_line.startswith("Actualizado el: "):
                    date_str = first_line.replace("Actualizado el: ", "").strip()
                    try:
                        last_update_date = datetime.datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S")
                        console_temp.print(f"Última actualización detectada: [cyan]{last_update_date}[/cyan]. Buscando nuevas CVEs.")
                    except ValueError:
                        console_temp.print("[yellow]Advertencia: No se pudo parsear la fecha de la última actualización.[/yellow]")

        # Lógica para llamar a la API de Vulners aquí
        # response = requests.post(vulners_api_url, json={...})
        # cves_raw_data = response.json().get('data', {}).get('docs', [])

        # Para la prueba, simulamos algunos datos
        simulated_cves = [
            {'id': 'CVE-2024-1234', 'description': 'Test CVE 1', 'published': '2024-01-01', 'cvss': '8.5', 'exploit': True, 'cwe': 'CWE-10'},
            {'id': 'CVE-2023-5678', 'description': 'Test CVE 2', 'published': '2023-05-10', 'cvss': '6.0', 'exploit': False, 'cwe': 'CWE-20'},
            {'id': 'CVE-2024-9999', 'description': 'Another recent CVE', 'published': '2024-02-15', 'cvss': '9.0', 'exploit': True, 'cwe': 'CWE-30'}
        ]

        # Aplicar filtros (ejemplo simplificado)
        filtered_cves = []
        for cve in simulated_cves:
            if float(cve.get('cvss', '0.0')) >= min_cvss_score and \
               int(cve.get('published', '2000-01-01').split('-')[0]) >= min_year:
                if not enable_exploit_filter or cve.get('exploit', False):
                    filtered_cves.append(cve)

        cves_data = filtered_cves # Usa tus datos reales aquí

        with open(cve_file_path, 'w', encoding='utf-8') as f:
            f.write(f"Actualizado el: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            for cve in cves_data:
                f.write(f"CVE-ID: {cve.get('id', 'N/A')}\n")
                f.write(f"  Descripción: {cve.get('description', 'N/A')}\n")
                f.write(f"  Publicado: {cve.get('published', 'N/A')}\n")
                f.write(f"  CVSSv3: {cve.get('cvss', 'N/A')}\n")
                f.write(f"  Con Exploit: {'Sí' if cve.get('exploit') else 'No'}\n")
                f.write(f"  CWE-ID: {cve.get('cwe', 'N/A')}\n") # Asegúrate de que tu CVEs tengan CWE
                f.write("---\n")

        console_temp.print(f"✅ {len(cves_data)} CVEs guardadas en [green]{cve_file_path}[/green].")

    except Exception as e:
        console_temp.print(f"[bold red]❌ Error durante la actualización de CVEs:[/bold red] {e}")


# Bloque de ejecución directa de actualizar_cves.py si se ejecuta por sí mismo
if __name__ == "__main__":
    console_temp = Console()
    console_temp.print(Panel(
        "[bold green]AETHERIS - Actualización de Base de Datos de CVEs[/bold green]",
        subtitle="Obteniendo la información más reciente de vulnerabilidades.",
        border_style="green"
    ))

    # Aquí, cargar la configuración de Aetheris si se ejecuta directamente
    # duplicamos la lógica de carga para que el script pueda ser autónomo
    config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config', 'aetheris.conf')
    local_config = configparser.ConfigParser()
    if os.path.exists(config_path):
        local_config.read(config_path)
    else:
        console_temp.print("[bold yellow]Advertencia: No se encontró 'aetheris.conf'. Usando valores por defecto para CVEs.[/bold yellow]")
        local_config['CVE_UPDATES'] = {} # Sección vacía para fallbacks
        local_config['GLOBAL'] = {'default_results_dir': 'results/', 'log_level': 'INFO'}
        local_config['REPORTING'] = {'language': 'es', 'formats': 'txt', 'template_dir': 'templates/'}
        local_config['NMAP'] = {}
        local_config['INTEGRATIONS'] = {}

    # Llamar a la función principal con la configuración cargada
    update_cve_database(local_config)
