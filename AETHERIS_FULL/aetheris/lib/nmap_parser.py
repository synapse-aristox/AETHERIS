import os
import xml.etree.ElementTree as ET

def parse_nmap_xml(xml_file_path):
    """
    Parsea un archivo XML de Nmap y extrae información detallada de los servicios abiertos.

    Args:
        xml_file_path (str): La ruta al archivo XML generado por Nmap.

    Returns:
        list: Una lista de diccionarios, donde cada diccionario representa un servicio abierto
              con detalles como 'ip', 'port', 'protocol', 'service', 'product', 'version'.
              Retorna una lista vacía si hay un error o no se encuentran servicios.
    """
    scanned_services = []
    try:
        tree = ET.parse(xml_file_path)
        root = tree.getroot()

        for host in root.findall('host'):
            ip_address = host.find('address').get('addr')
            
            for port in host.findall('.//port'): # Busca todos los elementos 'port' dentro del 'host'
                state = port.find('state')
                if state is not None and state.get('state') == 'open':
                    port_id = port.get('portid')
                    protocol = port.get('protocol')
                    
                    service_element = port.find('service')
                    service_name = service_element.get('name') if service_element is not None else 'unknown'
                    product = service_element.get('product') if service_element is not None and service_element.get('product') else 'unknown'
                    version = service_element.get('version') if service_element is not None and service_element.get('version') else 'unknown'

                    scanned_services.append({
                        'ip': ip_address,
                        'port': port_id,
                        'protocol': protocol,
                        'service': service_name,
                        'product': product,
                        'version': version
                    })
    except FileNotFoundError:
        print(f"❌ Error: Archivo XML no encontrado en '{xml_file_path}'.")
    except ET.ParseError as e:
        print(f"❌ Error al parsear el archivo XML '{xml_file_path}': {e}")
    except Exception as e:
        print(f"❗ Ocurrió un error inesperado al procesar el XML de Nmap: {e}")
        
    return scanned_services

# --- Bloque para pruebas rápidas (opcional) ---
if __name__ == "__main__":
    # 1. Crear un archivo XML de Nmap de ejemplo para la prueba
    test_xml_dir = "temp_nmap_test"
    os.makedirs(test_xml_dir, exist_ok=True)
    test_xml_file = os.path.join(test_xml_dir, "nmap_scan_example.xml")
    
    example_xml_content = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
<host starttime="1678886400" endtime="1678886405">
<status state="up" reason="echo-reply"/>
<address addr="192.168.1.100" addrtype="ipv4"/>
<hostnames><hostname name="test-host.local" type="user"/></hostnames>
<ports>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack" reason_ttl="0"/><service name="ssh" product="OpenSSH" version="8.9p1 Ubuntu 3" extrainfo="Ubuntu Linux" conf="10" method="table" cpe="cpe:/a:openssh:openssh:8.9p1"/></port>
<port protocol="tcp" portid="80"><state state="open" reason="syn-ack" reason_ttl="0"/><service name="http" product="Apache httpd" version="2.4.52" extrainfo="(Ubuntu) PHP/8.1.2" conf="10" method="table" cpe="cpe:/a:apache:http_server:2.4.52"/></port>
<port protocol="tcp" portid="443"><state state="open" reason="syn-ack" reason_ttl="0"/><service name="https" product="Apache httpd" version="2.4.52" extrainfo="(Ubuntu) PHP/8.1.2" conf="10" method="table" cpe="cpe:/a:apache:http_server:2.4.52"/></port>
<port protocol="tcp" portid="3306"><state state="open" reason="syn-ack" reason_ttl="0"/><service name="mysql" product="MySQL" version="8.0.32" extrainfo="for Linux on x86_64 (MySQL Community Server)" conf="10" method="table" cpe="cpe:/a:oracle:mysql:8.0.32"/></port>
<port protocol="tcp" portid="8080"><state state="closed" reason="conn-refused" reason_ttl="0"/><service name="http-proxy"/></port>
</ports>
</host>
<host starttime="1678886406" endtime="1678886410">
<status state="up" reason="echo-reply"/>
<address addr="192.168.1.101" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="21"><state state="open" reason="syn-ack" reason_ttl="0"/><service name="ftp" product="vsftpd" version="3.0.3" conf="10" method="table" cpe="cpe:/a:vsftpd_project:vsftpd:3.0.3"/></port>
</ports>
</host>
</nmaprun>
"""
    with open(test_xml_file, "w") as f:
        f.write(example_xml_content)

    print("\n--- Probando parse_nmap_xml ---")
    parsed_data = parse_nmap_xml(test_xml_file)

    if parsed_data:
        print("Servicios parseados:")
        for service in parsed_data:
            print(f"  IP: {service.get('ip')}, Port: {service.get('port')}, Protocol: {service.get('protocol')}, "
                  f"Service: {service.get('service')}, Product: {service.get('product')}, Version: {service.get('version')}")
    else:
        print("No se encontraron servicios o hubo un error al parsear.")

    # Limpiar archivos de prueba
    if os.path.exists(test_xml_file):
        os.remove(test_xml_file)
    if os.path.exists(test_xml_dir):
        os.rmdir(test_xml_dir)
    print("\nArchivos de prueba eliminados.")