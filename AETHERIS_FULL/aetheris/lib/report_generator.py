import os
import datetime
import json # Usaremos esto para cargar configuraciones si aetheris.conf es JSON
import configparser # O esto, si aetheris.conf es INI
from jinja2 import Environment, FileSystemLoader # Para plantillas HTML

# --- Configuración de idioma (preparación) ---
# En un escenario real, cargarías esto desde config/aetheris.conf
# Por ahora, para pruebas, definiremos un diccionario simple.
# Más adelante, se cargarían diccionarios completos desde archivos de idioma o el config.
TRANSLATIONS = {
    'es': {
        'report_title': "AETHERIS - Informe de Vulnerabilidades",
        'generated_on': "Generado el",
        'scan_target': "Objetivo de Escaneo",
        'total_vulnerabilities': "Total de Vulnerabilidades Potenciales Encontradas",
        'no_vulnerabilities': "No se encontraron vulnerabilidades potenciales en este escaneo.",
        'host': "HOST",
        'service_detected': "Servicio Detectado",
        'cve_identified': "CVE Identificada",
        'description': "Descripción",
        'published': "Publicación",
        'cvss_score': "CVSSv3 Score",
        'exploit_available': "Exploit Público Disponible",
        'yes': "Sí",
        'no': "No",
        'report_saved_to': "Informe de vulnerabilidades generado y guardado en",
        'error_writing_report': "Error al escribir el informe",
        'unexpected_error': "Ocurrió un error inesperado al generar el informe.",
        'unknown': "Desconocido",
        'no_description': "Sin descripción",
        'cwe_id': "CWE ID",
        'more_info': "Más información"
    },
    'en': {
        'report_title': "AETHERIS - Vulnerability Report",
        'generated_on': "Generated On",
        'scan_target': "Scan Target",
        'total_vulnerabilities': "Total Potential Vulnerabilities Found",
        'no_vulnerabilities': "No potential vulnerabilities were found in this scan.",
        'host': "HOST",
        'service_detected': "Service Detected",
        'cve_identified': "CVE Identified",
        'description': "Description",
        'published': "Published",
        'cvss_score': "CVSSv3 Score",
        'exploit_available': "Public Exploit Available",
        'yes': "Yes",
        'no': "No",
        'report_saved_to': "Vulnerability report generated and saved to",
        'error_writing_report': "Error writing report",
        'unexpected_error': "An unexpected error occurred while generating the report.",
        'unknown': "Unknown",
        'no_description': "No description",
        'cwe_id': "CWE ID",
        'more_info': "More Information"
    }
}

def get_translation(lang_code='es'):
    """Retorna el diccionario de traducción para el código de idioma dado."""
    return TRANSLATIONS.get(lang_code, TRANSLATIONS['es']) # Default a español si no se encuentra

def get_aetheris_config(config_file_path='config/aetheris.conf'):
    """
    Carga la configuración de Aetheris desde aetheris.conf.
    Prioriza el formato INI, si es JSON, se adaptaría.
    """
    config = configparser.ConfigParser()
    try:
        # Asegúrate de que la ruta sea relativa a la raíz del proyecto
        # Si report_generator.py está en lib/, entonces 'config/' es '../config/'
        absolute_config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), config_file_path)
        
        if not os.path.exists(absolute_config_path):
            print(f"⚠️ Advertencia: Archivo de configuración '{absolute_config_path}' no encontrado. Usando valores por defecto.")
            return {'language': 'es', 'report_formats': 'txt'} # Valores por defecto
        
        config.read(absolute_config_path)
        
        lang = config.get('REPORTING', 'language', fallback='es').lower()
        formats = config.get('REPORTING', 'formats', fallback='txt').lower()
        
        return {'language': lang, 'report_formats': formats}
    except Exception as e:
        print(f"❌ Error al cargar la configuración de Aetheris: {e}. Usando valores por defecto.")
        return {'language': 'es', 'report_formats': 'txt'} # Fallback

def generate_vulnerability_report(vulnerabilities_found, report_base_path, target_info=""):
    """
    Genera informes de vulnerabilidades en los formatos configurados (TXT, HTML).

    Args:
        vulnerabilities_found (list): Lista de diccionarios con los hallazgos de vulnerabilidades.
        report_base_path (str): La ruta base para los informes (ej. 'resultados/IP_TIMESTAMP/').
                                El nombre del archivo se construirá con la extensión.
        target_info (str): Información sobre el objetivo del escaneo (ej. IP o IP_TIMESTAMP).
    """
    aetheris_config = get_aetheris_config()
    lang = aetheris_config['language']
    report_formats = [fmt.strip() for fmt in aetheris_config['report_formats'].split(',')]
    _ = get_translation(lang) # Obtener las traducciones para el idioma seleccionado

    # Agrupar hallazgos por IP para una mejor legibilidad en ambos formatos
    findings_by_ip = {}
    for finding in vulnerabilities_found:
        ip = finding.get('ip', 'N/A')
        if ip not in findings_by_ip:
            findings_by_ip[ip] = []
        
        # Añadir URL de MITRE y CWE si existe
        cve_id = finding.get('cve_id', '')
        if cve_id and cve_id != 'N/A':
            finding['cve_mitre_url'] = f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}"
        else:
            finding['cve_mitre_url'] = None # No hay URL si no hay CVE ID

        # Asegurarse de que 'cwe_id' exista en el diccionario de finding
        # (Depende de si 'cve_matcher.py' lo añade o si lo tenemos de la base de datos de CVEs)
        if 'cwe_id' not in finding:
             finding['cwe_id'] = 'N/A' # Default si no está presente

        findings_by_ip[ip].append(finding)


    for fmt in report_formats:
        if fmt == 'txt':
            _generate_txt_report(vulnerabilities_found, report_base_path + ".txt", target_info, findings_by_ip, _)
        elif fmt == 'html':
            _generate_html_report(vulnerabilities_found, report_base_path + ".html", target_info, findings_by_ip, _)
        # elif fmt == 'pdf':
        #     _generate_pdf_report(vulnerabilities_found, report_base_path + ".pdf", target_info, findings_by_ip, _)
        else:
            print(f"⚠️ Formato de reporte '{fmt}' no soportado. Saltando.")


def _generate_txt_report(vulnerabilities_found, report_file_path, target_info, findings_by_ip, _):
    """Genera el informe en formato de texto plano."""
    try:
        with open(report_file_path, 'w', encoding='utf-8') as f:
            f.write(f"{_['report_title']}\n")
            f.write(f"{_['generated_on']}: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"{_['scan_target']}: {target_info if target_info else _['unknown']}\n")
            f.write("-" * 80 + "\n\n")

            if not vulnerabilities_found:
                f.write(f"{_['no_vulnerabilities']}\n")
            else:
                f.write(f"{_['total_vulnerabilities']}: {len(vulnerabilities_found)}\n\n")
                
                for ip, findings in findings_by_ip.items():
                    f.write(f"{_['host']}: {ip}\n")
                    f.write("=" * (len(f"{_['host']}: {ip}") + 4) + "\n\n")

                    for finding in findings:
                        service_name = finding.get('service_name', _['unknown'])
                        product = finding.get('product', _['unknown'])
                        version = finding.get('version', _['unknown'])
                        port = finding.get('port', _['unknown'])
                        protocol = finding.get('protocol', 'tcp')

                        cve_id = finding.get('cve_id', _['unknown'])
                        cve_desc = finding.get('cve_desc', _['no_description'])
                        cve_pub = finding.get('cve_pub', _['unknown'])
                        cve_cvss = finding.get('cve_cvss', 'N/A')
                        cve_exploit = _['yes'] if finding.get('cve_exploit') else _['no']
                        cwe_id = finding.get('cwe_id', 'N/A') # Nuevo

                        f.write(f"  {_['service_detected']}: {product} {version} ({service_name}) en {port}/{protocol}\n")
                        f.write(f"  {_['cve_identified']}: {cve_id}")
                        if finding.get('cve_mitre_url'):
                             f.write(f" ({finding['cve_mitre_url']})\n")
                        else:
                            f.write("\n")
                        f.write(f"    {_['cwe_id']}: {cwe_id}\n") # Nuevo
                        f.write(f"    {_['description']}: {cve_desc}\n")
                        f.write(f"    {_['published']}: {cve_pub}\n")
                        f.write(f"    {_['cvss_score']}: {cve_cvss}\n")
                        f.write(f"    {_['exploit_available']}: {cve_exploit}\n")
                        f.write("-" * 70 + "\n")
                    f.write("\n")
            
            f.write("\n" + "-" * 80 + "\n")
            f.write(":: Powered by AMADEUS // Operated by NyxKraken ::\n")
            f.write(f"{_['report_saved_to']}: {report_file_path}\n")

        print(f"✅ Informe TXT generado y guardado en: {report_file_path}")

    except IOError as e:
        print(f"❌ {_['error_writing_report']} '{report_file_path}': {e}")
    except Exception as e:
        print(f"❗ {_['unexpected_error']} TXT: {e}")

def _generate_html_report(vulnerabilities_found, report_file_path, target_info, findings_by_ip, _):
    """Genera el informe en formato HTML usando una plantilla Jinja2."""
    try:
        # Configura Jinja2 para cargar plantillas desde la carpeta 'templates'
        # La ruta debe ser relativa desde donde se ejecuta aetheris_main.py (raíz del proyecto)
        # o desde lib/report_generator.py (retroceder un nivel)
        template_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'templates')
        env = Environment(loader=FileSystemLoader(template_dir))
        template = env.get_template('reporte_html.html') # Asegúrate que este archivo exista en templates/

        # Datos para pasar a la plantilla HTML
        report_data = {
            'title': _['report_title'],
            'generated_on': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'scan_target': target_info if target_info else _['unknown'],
            'total_vulnerabilities': len(vulnerabilities_found) if vulnerabilities_found else 0,
            'no_vulnerabilities_message': _['no_vulnerabilities'],
            'findings_by_ip': findings_by_ip, # Los datos agrupados
            'translations': _, # Pasar todo el diccionario de traducciones
            'powered_by': ":: Powered by AMADEUS // Operated by NyxKraken ::"
        }

        output_html = template.render(report_data)

        with open(report_file_path, 'w', encoding='utf-8') as f:
            f.write(output_html)

        print(f"✅ Informe HTML generado y guardado en: {report_file_path}")

    except Exception as e:
        print(f"❗ {_['unexpected_error']} HTML: {e}")
        print(f"Asegúrate de que 'reporte_html.html' exista en la carpeta 'templates/' y sea accesible.")


# --- Bloque para pruebas rápidas (opcional) ---
if __name__ == "__main__":
    # Necesitas instalar Jinja2 para la parte HTML: pip install Jinja2
    
    # 1. Crear un aetheris.conf de ejemplo para la prueba en la carpeta 'config/'
    #    (La ruta de config_file_path en get_aetheris_config() asume que aetheris.conf está en ../config/aetheris.conf)
    test_config_dir = "../config"
    os.makedirs(test_config_dir, exist_ok=True)
    test_config_file_path = os.path.join(test_config_dir, "aetheris.conf")
    with open(test_config_file_path, "w") as f:
        f.write("[REPORTING]\n")
        f.write("language = es\n") # Cambia a 'en' para probar inglés
        f.write("formats = txt, html\n") # Cambia a 'txt' o 'html' para probar individualmente

    # 2. Simular una lista de hallazgos de vulnerabilidades (con CWE y datos para URL)
    test_findings = [
        {
            'ip': '192.168.1.100', 'port': '80', 'protocol': 'tcp', 'service_name': 'http', 'product': 'Apache httpd', 'version': '2.4.52',
            'cve_id': 'CVE-2023-XXXXX', 'cve_desc': 'Apache HTTP Server 2.4.52 mod_proxy_ajp vulnerability', 'cve_pub': '2023-01-01',
            'cve_cvss': '9.8', 'cve_exploit': True, 'cwe_id': 'CWE-22' # Nuevo CWE
        },
        {
            'ip': '192.168.1.100', 'port': '22', 'protocol': 'tcp', 'service_name': 'ssh', 'product': 'OpenSSH', 'version': '8.9p1',
            'cve_id': 'CVE-2022-YYYYY', 'cve_desc': 'OpenSSH 8.9 vulnerability in ssh-agent, possibly leading to RCE', 'cve_pub': '2022-03-15',
            'cve_cvss': '7.5', 'cve_exploit': False, 'cwe_id': 'CWE-77'
        },
        {
            'ip': '192.168.1.101', 'port': '3306', 'protocol': 'tcp', 'service_name': 'mysql', 'product': 'MySQL', 'version': '8.0.32',
            'cve_id': 'CVE-2021-ZZZZZ', 'cve_desc': 'MySQL 8.0.32 authentication bypass vulnerability', 'cve_pub': '2021-11-20',
            'cve_cvss': '9.0', 'cve_exploit': True, 'cwe_id': 'CWE-287'
        },
        {
            'ip': '192.168.1.102', 'port': '8080', 'protocol': 'tcp', 'service_name': 'http-proxy', 'product': 'nginx', 'version': '1.18.0',
            'cve_id': 'CVE-2023-5555', 'cve_desc': 'Nginx HTTP/2 Rapid Reset Attack fix', 'cve_pub': '2023-10-26',
            'cve_cvss': '7.5', 'cve_exploit': True, 'cwe_id': 'CWE-400'
        },
        { # Servicio sin CVE
            'ip': '192.168.1.105', 'port': '53', 'protocol': 'udp', 'service_name': 'domain', 'product': 'ISC BIND', 'version': '9.16.1',
            'cve_id': 'N/A', 'cve_desc': 'No CVE Found', 'cve_pub': 'N/A', 'cve_cvss': 'N/A', 'cve_exploit': False, 'cwe_id': 'N/A'
        }
    ]

    # Define una ruta de salida temporal para la prueba (simulando resultados/IP_TIMESTAMP/)
    test_output_base_dir = "temp_report_test/192.168.1.X_TEST_SCAN"
    os.makedirs(test_output_base_dir, exist_ok=True)
    test_report_base_path = os.path.join(test_output_base_dir, "vuln_report") # Sin extensión

    print("\n--- Probando generate_vulnerability_report (TXT y HTML) ---")
    generate_vulnerability_report(test_findings, test_report_base_path, "192.168.1.X_TEST_SCAN")

    # Prueba con una lista vacía
    print("\n--- Probando generate_vulnerability_report (sin hallazgos) ---")
    test_output_empty_dir = "temp_report_test/192.168.1.Y_EMPTY_SCAN"
    os.makedirs(test_output_empty_dir, exist_ok=True)
    test_report_empty_base_path = os.path.join(test_output_empty_dir, "vuln_report")
    generate_vulnerability_report([], test_report_empty_base_path, "192.168.1.Y_EMPTY_SCAN")

    # Limpiar archivos y carpeta de prueba
    print(f"\n--- Limpiando archivos de prueba en '{test_output_base_dir}' y '{test_output_empty_dir}' ---")
    if os.path.exists(test_report_base_path + ".txt"):
        os.remove(test_report_base_path + ".txt")
    if os.path.exists(test_report_base_path + ".html"):
        os.remove(test_report_base_path + ".html")
    if os.path.exists(test_report_empty_base_path + ".txt"):
        os.remove(test_report_empty_base_path + ".txt")
    if os.path.exists(test_report_empty_base_path + ".html"):
        os.remove(test_report_empty_base_path + ".html")

    # Eliminar directorios si están vacíos
    import shutil
    if os.path.exists(test_output_base_dir):
        shutil.rmtree(test_output_base_dir) # Elimina directorio y contenido
    if os.path.exists(test_output_empty_dir):
        shutil.rmtree(test_output_empty_dir)
    if os.path.exists(test_config_dir):
        shutil.rmtree(test_config_dir) # Eliminar la carpeta config de prueba también

    print("Archivos y directorios de prueba eliminados.")