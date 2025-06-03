# aetheris/analizar_vs_scan.py
import os
# Importamos las funciones desde los módulos de la librería
from lib.nmap_parser import parse_nmap_xml # Usaremos esta en lugar de parse_nmap_services
from lib.cve_matcher import load_cves, match_services_with_cves # Moveremos load_cves y match_services_with_cves aquí
from lib.report_generator import generate_vulnerability_report # Función para generar el informe

def run_analysis(xml_path, cve_path="cves_actuales.txt", output_dir=None):
    """
    Ejecuta el análisis comparando servicios de Nmap con la base de datos de CVEs.

    Args:
        xml_path (str): Ruta al archivo XML de Nmap.
        cve_path (str): Ruta al archivo de la base de datos de CVEs.
        output_dir (str, optional): Directorio donde guardar el vuln_report.txt.
                                   Si es None, se intentará deducir del xml_path.
    """
    print("🔍 AETHERIS – Análisis de servicios vs CVEs")

    if not os.path.isfile(xml_path):
        print(f"❌ Error: Archivo XML no encontrado en '{xml_path}'.")
        return

    if not os.path.isfile(cve_path):
        print(f"❌ Error: Archivo de CVEs no encontrado en '{cve_path}'. Ejecuta primero actualizar_cves.py.")
        return

    print("📥 Analizando servicios detectados por Nmap...")
    # Usamos la función parse_nmap_xml de lib/nmap_parser.py
    servicios_detectados = parse_nmap_xml(xml_path) 
    print(f"✅ {len(servicios_detectados)} servicios abiertos detectados.")

    if not servicios_detectados:
        print("No se encontraron servicios abiertos para analizar.")
        return

    print("📚 Cargando base de datos de CVEs...")
    # Usamos la función load_cves (que se movería a cve_matcher.py)
    cves_db = load_cves(cve_path)
    print(f"✅ {len(cves_db)} CVEs cargadas.")

    if not cves_db:
        print("La base de datos de CVEs está vacía. Asegúrate de actualizarla.")
        return

    print("🔎 Buscando coincidencias entre servicios y CVEs...")
    # Usamos la función match_services_with_cves (que se movería a cve_matcher.py)
    vulnerabilidades_encontradas = match_services_with_cves(servicios_detectados, cves_db)

    if vulnerabilidades_encontradas:
        print(f"🚨 {len(vulnerabilidades_encontradas)} vulnerabilidades potenciales encontradas:")
        for finding in vulnerabilidades_encontradas:
            print(f"🛠 Servicio: {finding['service_name']} (Producto: {finding['product']}, Versión: {finding['version']})")
            print(f"   ↪ CVE: {finding['cve_id']} – {finding['cve_desc']}")
            print(f"   ↪ Publicado: {finding.get('cve_pub', '-')}, CVSSv3: {finding.get('cve_cvss', '-')}, Exploit: {finding.get('cve_exploit', '-')}")
            print("-" * 60)
    else:
        print("✅ No se encontraron coincidencias relevantes con las CVEs actuales.")

    # Generar el informe de vulnerabilidades
    if output_dir is None:
        # Intenta deducir el directorio de salida si no se proporciona
        output_dir = os.path.dirname(xml_path) 
    
    report_file_path = os.path.join(output_dir, "vuln_report.txt")
    # Usa la función generate_vulnerability_report de lib/report_generator.py
    generate_vulnerability_report(vulnerabilidades_encontradas, report_file_path, os.path.basename(os.path.dirname(output_dir))) # Pasa el IP del objetivo
    print(f"\n💾 Informe de vulnerabilidades guardado en: {report_file_path}")

# Bloque para ejecución directa del script
if __name__ == "__main__":
    # Esto simula cómo se llamaría desde aetheris_main.py o directamente
    # Para probar, necesitas un archivo XML de Nmap y el cves_actuales.txt
    
    # Ejemplo de uso (AJUSTA LAS RUTAS SEGÚN TU ESTRUCTURA LOCAL)
    # Por ejemplo, si tienes un escaneo Nmap en:
    # aetheris/resultados/192.168.1.1_20240602_150000/nmap_scan_192.168.1.1.xml
    # Y tu cves_actuales.txt está en: aetheris/cves_actuales.txt
    
    # Asegúrate de haber ejecutado actualizar_cves.py al menos una vez para tener cves_actuales.txt

    # Ruta de ejemplo para el XML de Nmap (AJUSTA ESTO)
    # nmap_xml_test_path = "ruta/a/tu/archivo_nmap.xml" 
    # cves_file_test_path = "../cves_actuales.txt" # Asumiendo que analizador_vs_scan.py está en la raíz de aetheris/

    # --- Creación de un XML de ejemplo y cves_actuales.txt para prueba ---
    # Esto es solo para que el script pueda correr sin Nmap real
    # En un entorno real, usarías el XML generado por Nmap
    
    # 1. Crear un directorio de ejemplo para resultados
    test_target_dir = "temp_test_results/127.0.0.1_test_scan"
    os.makedirs(test_target_dir, exist_ok=True)
    test_xml_file = os.path.join(test_target_dir, "nmap_scan_127.0.0.1.xml")
    
    # Contenido XML de ejemplo (simple)
    example_xml_content = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
<host starttime="1678886400" endtime="1678886405">
<status state="up" reason="echo-reply"/>
<address addr="127.0.0.1" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="8.9p1" /></port>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Apache httpd" version="2.4.52" /></port>
<port protocol="tcp" portid="3306"><state state="open"/><service name="mysql" product="MySQL" version="8.0.32" /></port>
</ports>
</host>
</nmaprun>
"""
    with open(test_xml_file, "w") as f:
        f.write(example_xml_content)

    # 2. Crear un cves_actuales.txt de ejemplo
    test_cves_file = "temp_cves_actuales.txt"
    example_cves_content = """Actualizado el: 2025-06-02 16:00:00

CVE-ID: CVE-2023-XXXXX
  Descripción: Apache HTTP Server 2.4.52 mod_proxy_ajp vulnerability
  Publicado: 2023-01-01
  CVSSv3: 9.8
  Con Exploit: Sí
---
CVE-ID: CVE-2022-YYYYY
  Descripción: OpenSSH 8.9 vulnerability in ssh-agent
  Publicado: 2022-03-15
  CVSSv3: 7.5
  Con Exploit: No
---
CVE-ID: CVE-2021-ZZZZZ
  Descripción: MySQL 8.0.32 authentication bypass
  Publicado: 2021-11-20
  CVSSv3: 9.0
  Con Exploit: Sí
---
CVE-ID: CVE-2024-ABCDE
  Descripción: General Linux kernel vulnerability
  Publicado: 2024-05-01
  CVSSv3: 8.0
  Con Exploit: No
---
"""
    with open(test_cves_file, "w", encoding="utf-8") as f:
        f.write(example_cves_content)

    print("\n--- Ejecutando análisis de prueba ---")
    run_analysis(test_xml_file, test_cves_file, test_target_dir)

    # --- Limpiar archivos de prueba ---
    print("\n--- Limpiando archivos de prueba ---")
    os.remove(test_xml_file)
    os.remove(test_cves_file)
    # os.rmdir(test_target_dir) # Ojo: rmdir solo si está vacío. Para eliminar directorios no vacíos se usa shutil.rmtree
    print("Archivos de prueba eliminados.")