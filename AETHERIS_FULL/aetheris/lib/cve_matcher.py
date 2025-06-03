import os

def load_cves(cves_file_path):
    """
    Carga la base de datos de CVEs desde el archivo cves_actuales.txt.

    Args:
        cves_file_path (str): La ruta al archivo cves_actuales.txt.

    Returns:
        list: Una lista de diccionarios, donde cada diccionario representa una CVE.
              Devuelve una lista vacía si el archivo no existe o hay un error.
    """
    cve_db = []
    if not os.path.isfile(cves_file_path):
        print(f"❌ Error: El archivo de CVEs no fue encontrado en '{cves_file_path}'.")
        return cve_db

    try:
        with open(cves_file_path, "r", encoding="utf-8") as f:
            entry = {}
            for line in f:
                line = line.strip()
                if line.startswith("CVE-ID:"):
                    if entry: # Si ya hay una CVE en proceso, la añadimos y empezamos una nueva
                        cve_db.append(entry)
                        entry = {}
                    entry["id"] = line.split("CVE-ID:")[1].strip()
                elif line.startswith("Descripción:"):
                    entry["desc"] = line.split("Descripción:")[1].strip()
                elif line.startswith("Publicado:"):
                    entry["pub"] = line.split("Publicado:")[1].strip()
                elif line.startswith("CVSSv3:"):
                    entry["cvss"] = line.split("CVSSv3:")[1].strip()
                elif line.startswith("Con Exploit:"):
                    # Convertir 'Sí'/'No' a booleano para mejor manejo
                    entry["exploit"] = True if line.split("Con Exploit:")[1].strip().lower() == "sí" else False
            if entry: # Asegurarse de añadir la última entrada
                cve_db.append(entry)
    except Exception as e:
        print(f"⚠️ Error al leer el archivo de CVEs '{cves_file_path}': {e}")
    return cve_db

def match_services_with_cves(scanned_services, cves_db):
    """
    Compara los servicios detectados con la base de datos de CVEs cargada.
    Realiza un matching inteligente por producto y, si es posible, versión.

    Args:
        scanned_services (list): Lista de diccionarios de servicios detectados por Nmap
                                 (ej., [{'ip': '...', 'product': 'Apache', 'version': '2.4.52', ...}]).
        cves_db (list): Lista de diccionarios de CVEs (ej., [{'id': 'CVE-2023-XXXXX', 'desc': '...', ...}]).

    Returns:
        list: Una lista de diccionarios con los hallazgos de vulnerabilidades.
              Cada diccionario contiene detalles del servicio y la CVE coincidente.
    """
    vulnerable_findings = []

    for service_data in scanned_services:
        product_name = service_data.get('product', '').lower()
        service_name = service_data.get('service', '').lower() # A veces product está vacío, pero service tiene algo
        version = service_data.get('version', '').lower()
        ip = service_data.get('ip', 'N/A')
        port = service_data.get('port', 'N/A')

        if not (product_name or service_name): # Si no hay ni producto ni servicio, no podemos buscar
            continue

        for cve in cves_db:
            cve_desc = cve.get('desc', '').lower()
            cve_id = cve.get('id', 'N/A')

            # Estrategia de Matching Inteligente:
            # 1. Intentar matching exacto por producto y versión si la versión está disponible.
            # 2. Si no, intentar matching por producto y nombre de servicio.
            # 3. Finalmente, un matching más general solo por producto o servicio.

            # Coincidencia por PRODUCTO (o servicio) y VERSION (si disponible)
            found_match = False
            if version:
                # Intenta encontrar el producto Y la versión en la descripción de la CVE
                if (product_name and product_name in cve_desc and version in cve_desc) or \
                   (service_name and service_name in cve_desc and version in cve_desc):
                    found_match = True
            
            # Si no se encontró por versión, intenta solo por PRODUCTO (o servicio)
            if not found_match:
                if (product_name and product_name in cve_desc) or \
                   (service_name and service_name in cve_desc):
                    found_match = True

            # Se puede añadir más lógicas aquí, como:
            # - Matching parcial de versiones (ej. "2.4" para "2.4.52")
            # - Exclusiones (ej. si la CVE menciona "Windows" y el servicio es de Linux)

            if found_match:
                finding = {
                    'ip': ip,
                    'port': port,
                    'service_name': service_data.get('service'),
                    'product': service_data.get('product'),
                    'version': service_data.get('version'),
                    'cve_id': cve_id,
                    'cve_desc': cve.get('desc'),
                    'cve_pub': cve.get('pub'),
                    'cve_cvss': cve.get('cvss'),
                    'cve_exploit': cve.get('exploit')
                }
                vulnerable_findings.append(finding)
                # Opcional: break aquí si solo se quiere la primera CVE encontrada por servicio
                # break # Esto detiene la búsqueda de CVEs para el servicio actual una vez que se encuentra una coincidencia.
                        # Si se quiere encontrar TODAS las CVEs para UN servicio, NO usar break.

    return vulnerable_findings

# --- Bloque para pruebas rápidas (opcional) ---
if __name__ == "__main__":
    # Se necesita un archivo cves_actuales.txt y datos de servicios parseados
    # para probar este módulo de forma independiente.

    # 1. Crear un archivo cves_actuales.txt de ejemplo para la prueba
    test_cves_file = "../cves_actuales.txt" # En la raíz de aetheris
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
CVE-ID: CVE-2020-0001
  Descripción: Old Tomcat vulnerability in version 8.0.0
  Publicado: 2020-01-01
  CVSSv3: 6.0
  Con Exploit: No
---
CVE-ID: CVE-2023-5555
  Descripción: Nginx HTTP/2 Rapid Reset Attack fix
  Publicado: 2023-10-26
  CVSSv3: 7.5
  Con Exploit: Sí
---
"""
    with open(test_cves_file, "w", encoding="utf-8") as f:
        f.write(example_cves_content)

    # 2. Datos de servicios detectados (simulando la salida de nmap_parser.py)
    test_scanned_services = [
        {'ip': '192.168.1.100', 'port': '80', 'protocol': 'tcp', 'service': 'http', 'product': 'Apache httpd', 'version': '2.4.52'},
        {'ip': '192.168.1.100', 'port': '22', 'protocol': 'tcp', 'service': 'ssh', 'product': 'OpenSSH', 'version': '8.9p1'},
        {'ip': '192.168.1.101', 'port': '3306', 'protocol': 'tcp', 'service': 'mysql', 'product': 'MySQL', 'version': '8.0.32'},
        {'ip': '192.168.1.102', 'port': '8080', 'protocol': 'tcp', 'service': 'http-proxy', 'product': 'nginx', 'version': '1.18.0'},
        {'ip': '192.168.1.103', 'port': '443', 'protocol': 'tcp', 'service': 'https', 'product': 'Apache httpd', 'version': '2.4.58'}, # Nueva versión
        {'ip': '192.168.1.104', 'port': '8009', 'protocol': 'tcp', 'service': 'ajp', 'product': 'Apache Tomcat', 'version': '9.0.50'},
        {'ip': '192.168.1.105', 'port': '53', 'protocol': 'udp', 'service': 'domain', 'product': 'ISC BIND', 'version': '9.16.1'},
    ]

    print("\n--- Probando match_services_with_cves ---")
    cves_data = load_cves(test_cves_file)
    if cves_data:
        findings = match_services_with_cves(test_scanned_services, cves_data)
        if findings:
            for f in findings:
                print(f"[{f['ip']}:{f['port']}] {f['product']} {f['version']} -> CVE: {f['cve_id']} ({f['cve_desc']}) [CVSS: {f['cve_cvss']} | Exploit: {'Sí' if f['cve_exploit'] else 'No'}]")
        else:
            print("No se encontraron coincidencias en la prueba.")
    else:
        print("No se pudieron cargar las CVEs para la prueba.")

    # --- Limpiar el archivo de prueba ---
    if os.path.exists(test_cves_file):
        os.remove(test_cves_file)
        print(f"\nArchivo de prueba '{test_cves_file}' eliminado.")
