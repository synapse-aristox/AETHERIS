# aetheris/lib/utils.py
import os
import re
from datetime import datetime
import shutil
import logging
import logging.handlers # Para RotatingFileHandler
import ipaddress

# Intentar importar unidecode para slugify, es opcional
try:
    from unidecode import unidecode
except ImportError:
    unidecode = None # Si no está disponible, unidecode será None


# --- Configuración básica del logging ---
# Esta función debe llamarse una única vez al inicio de la aplicación (en aetheris_main.py)
def setup_logging(log_level='INFO', log_file_path=None):
    """
    Configura el logger principal para Aetheris.

    Args:
        log_level (str): Nivel mínimo de log (INFO, DEBUG, WARNING, ERROR, CRITICAL).
        log_file_path (str, opcional): Ruta al archivo donde se guardarán los logs.
                                        Si es None, solo se loguea en consola.
    Returns:
        logging.Logger: La instancia del logger configurado.
    """
    logger = logging.getLogger('aetheris')
    logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))

    # Evitar añadir múltiples handlers si ya existen (importante para evitar logs duplicados)
    if not logger.handlers:
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

        # Handler para la consola
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
        
        # Handler para el archivo de log (opcional)
        if log_file_path:
            try:
                # Asegurarse de que el directorio del log exista
                log_dir = os.path.dirname(log_file_path)
                if log_dir and not os.path.exists(log_dir):
                    os.makedirs(log_dir)

                # Usar RotatingFileHandler para evitar que el archivo de log crezca indefinidamente
                file_handler = logging.handlers.RotatingFileHandler(
                    log_file_path, 
                    maxBytes=10*1024*1024, # 10 MB por archivo
                    backupCount=5,         # Mantener hasta 5 archivos de backup
                    encoding='utf-8'
                )
                file_handler.setFormatter(formatter)
                logger.addHandler(file_handler)
            except Exception as e:
                # No podemos usar el logger aquí porque podría ser el problema,
                # así que usamos print a stderr.
                import sys
                print(f"ERROR: No se pudo configurar el archivo de log en '{log_file_path}': {e}", file=sys.stderr)
                # Opcionalmente, lanzar la excepción si es un error crítico
                # raise

    return logger

# Se obtiene una instancia del logger global de Aetheris.
# Esta es la instancia que otros módulos importarán y usarán para loguear mensajes.
# NOTA: La configuración real (handlers, nivel) debe hacerse llamando a setup_logging() en aetheris_main.py.
aetheris_logger = logging.getLogger('aetheris')


# --- Funciones de Validación ---
def validate_ip(ip):
    """
    Valida una dirección IP IPv4.

    Args:
        ip (str): La cadena de la dirección IP.

    Returns:
        bool: True si es una IP IPv4 válida, False en caso contrario.
    """
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ipaddress.AddressValueError:
        return False


def validate_port(port):
    """
    Valida que un puerto esté en el rango 1-65535.

    Args:
        port (str o int): El número de puerto.

    Returns:
        bool: True si el puerto es válido, False en caso contrario.
    """
    try:
        port_int = int(port)
        return 1 <= port_int <= 65535
    except ValueError:
        return False

def validate_subnet(subnet_cidr):
    """
    Valida una subred en formato CIDR (IPv4).

    Args:
        subnet_cidr (str): La cadena de la subred en formato CIDR (ej. "192.168.1.0/24").

    Returns:
        bool: True si es una subred IPv4 CIDR válida, False en caso contrario.
    """
    try:
        ipaddress.IPv4Network(subnet_cidr, strict=False) # strict=False permite host bits
        return True
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
        return False


# --- Funciones de Utilidad de Archivos/Nombres ---
def get_timestamp():
    """
    Devuelve un timestamp legible para nombrar carpetas o archivos (YYYYMMDD_HHMMSS).

    Returns:
        str: El timestamp actual formateado.
    """
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def ensure_directory(path):
    """
    Crea el directorio si no existe. Es idempotente.

    Args:
        path (str): La ruta del directorio a asegurar.
    """
    os.makedirs(path, exist_ok=True)


def slugify(text):
    """
    Convierte un texto en un 'slug' seguro para nombres de archivo/directorio.
    Reemplaza caracteres no alfanuméricos por guiones y convierte a minúsculas.
    Si la librería 'unidecode' está instalada, también normaliza caracteres acentuados.

    Args:
        text (str): El texto de entrada.

    Returns:
        str: El texto convertido a un slug.
    """
    # Intentar normalizar caracteres acentuados a ASCII si unidecode está disponible
    if unidecode:
        text = unidecode(text)

    # Eliminar cualquier caracter que no sea alfanumérico, espacio o guion
    text = re.sub(r'[^\w\s-]', '', text).strip().lower()
    # Reemplazar espacios y guiones múltiples con un solo guion
    text = re.sub(r'[\s_-]+', '-', text)
    return text


def extract_target_ip_from_path(path):
    """
    Extrae la IP objetivo desde un path tipo 'resultados/199.100.1.100_20240602_150000/'.

    Args:
        path (str): La ruta completa o parcial del directorio de resultados.

    Returns:
        str: La dirección IP extraída, o "Unknown" si no se puede validar.
    """
    base = os.path.basename(os.path.normpath(path))
    ip_candidate = base.split("_")[0]
    
    # Usar la nueva función validate_ip para verificar la IP
    return ip_candidate if validate_ip(ip_candidate) else "Unknown"


def is_public_ip(target: str) -> bool:
    """
    Verifica si una dirección IP o un rango CIDR es probablemente público.
    Considera una IP/rango como público si no cae dentro de los rangos RFC1918 o localhost.

    Args:
        target (str): La dirección IP o rango CIDR a verificar.

    Returns:
        bool: True si la IP/rango es probablemente pública, False si es privada o loopback.
    """
    try:
        if '/' in target:
            # Si es un rango CIDR, crea un objeto de red.
            network = ipaddress.ip_network(target, strict=False)
            # Retorna True si la red NO es privada (RFC 1918) y NO es loopback.
            # ipaddress.ip_network.is_private ya cubre los rangos RFC 1918
            # y también incluye redes loopback (como 127.0.0.0/8).
            return not network.is_private
        else:
            # Si es una IP única, crea un objeto de dirección.
            ip_addr = ipaddress.ip_address(target)
            # Retorna True si la IP NO es privada (RFC 1918) y NO es loopback.
            return not (ip_addr.is_private or ip_addr.is_loopback)
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
        # Si la entrada no es una IP o CIDR válida, no podemos determinar si es pública.
        # Para evitar escanear algo "público" accidentalmente, es más seguro asumir que no lo es
        # o que hay un error en la entrada, y reportarlo.
        aetheris_logger.warning(f"'{target}' no es un formato IP/CIDR válido para verificar su publicabilidad.")
        return False


# --- Bloque para pruebas rápidas (opcional) ---
if __name__ == "__main__":
    # Configurar un logger básico para las pruebas del módulo utils.py
    test_logger = logging.getLogger('utils_test_runner')
    if not test_logger.handlers: # Evitar handlers duplicados en caso de re-ejecución en el mismo proceso
        test_logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        test_logger.addHandler(handler)

    test_logger.info("--- Probando funciones de utils.py ---")

    test_logger.info("\nValidación de IP:")
    test_logger.info(f"192.168.1.1 es válido: {validate_ip('192.168.1.1')}")
    test_logger.info(f"256.0.0.1 es válido: {validate_ip('256.0.0.1')}")
    test_logger.info(f"abc.def.g.h es válido: {validate_ip('abc.def.g.h')}")
    test_logger.info(f"10.0.0.255 es válido: {validate_ip('10.0.0.255')}")

    test_logger.info("\nValidación de Puerto:")
    test_logger.info(f"80 es válido: {validate_port(80)}")
    test_logger.info(f"65536 es válido: {validate_port(65536)}")
    test_logger.info(f"0 es válido: {validate_port(0)}")
    test_logger.info(f"'abc' es válido: {validate_port('abc')}")

    test_logger.info("\nValidación de Subred (CIDR):")
    test_logger.info(f"192.168.1.0/24 es válido: {validate_subnet('192.168.1.0/24')}")
    test_logger.info(f"10.0.0.0/8 es válido: {validate_subnet('10.0.0.0/8')}")
    test_logger.info(f"172.16.1.1/32 es válido: {validate_subnet('172.16.1.1/32')}")
    test_logger.info(f"invalid/24 es válido: {validate_subnet('invalid/24')}")
    test_logger.info(f"192.168.1.0/33 es válido: {validate_subnet('192.168.1.0/33')}")
    test_logger.info(f"192.168.1.0/0 es válido: {validate_subnet('192.168.1.0/0')}")


    test_logger.info("\nTimestamp:")
    test_logger.info(f"Timestamp actual: {get_timestamp()}")

    test_logger.info("\nCreación y Limpieza de Directorio de Prueba:")
    test_dir = "temp_test_dir_utils"
    ensure_directory(test_dir)
    test_logger.info(f"Directorio '{test_dir}' creado (o ya existía).")
    
    test_file_in_dir = os.path.join(test_dir, "test.txt")
    with open(test_file_in_dir, "w") as f:
        f.write("Esto es un archivo de prueba.")
    test_logger.info(f"Archivo '{test_file_in_dir}' creado.")

    if os.path.exists(test_dir):
        shutil.rmtree(test_dir)
        test_logger.info(f"Directorio '{test_dir}' y su contenido eliminado.")
    else:
        test_logger.warning(f"El directorio '{test_dir}' no se encontró después de la creación/limpieza.")


    test_logger.info("\nExtracción de IP de Path:")
    test_path1 = os.path.join("resultados", "192.168.1.100_20240602_150000", "nmap.xml")
    test_path2 = os.path.join("results", "unknown_host_20240602_160000")
    test_logger.info(f"IP de '{test_path1}': {extract_target_ip_from_path(test_path1)}")
    test_logger.info(f"IP de '{test_path2}': {extract_target_ip_from_path(test_path2)}")

    test_logger.info("\nSlugify:")
    test_logger.info(f"Original: 'Mi archivo con Espacios & Caracteres!' -> Slug: '{slugify('Mi archivo con Espacios & Caracteres!')}'")
    test_logger.info(f"Original: 'Otro Ejemplo.txt' -> Slug: '{slugify('Otro Ejemplo.txt')}'")
    test_logger.info(f"Original: 'Servicio Web v2.0' -> Slug: '{slugify('Servicio Web v2.0')}'")
    
    # Prueba con caracteres acentuados si unidecode está disponible
    if unidecode:
        test_logger.info(f"Original: 'Servidor Núcleo (áéíóúñ)' -> Slug: '{slugify('Servidor Núcleo (áéíóúñ)')}'")
    else:
        test_logger.info("Advertencia: 'unidecode' no está instalado. 'slugify' no normalizará caracteres acentuados.")
    
    test_logger.info("\nVerificación de IP Pública:")
    test_logger.info(f"192.168.1.1 (privada): {is_public_ip('192.168.1.1')}")
    test_logger.info(f"10.0.0.5/24 (privada): {is_public_ip('10.0.0.5/24')}")
    test_logger.info(f"172.16.0.10 (privada): {is_public_ip('172.16.0.10')}")
    test_logger.info(f"172.31.255.255 (privada): {is_public_ip('172.31.255.255')}")
    test_logger.info(f"127.0.0.1 (loopback): {is_public_ip('127.0.0.1')}")
    test_logger.info(f"8.8.8.8 (pública): {is_public_ip('8.8.8.8')}")
    test_logger.info(f"203.0.113.45/28 (pública): {is_public_ip('203.0.113.45/28')}")
    test_logger.info(f"0.0.0.0 (no especificada): {is_public_ip('0.0.0.0')}") # is_private=True
    test_logger.info(f"invalid-ip (inválida): {is_public_ip('invalid-ip')}")

    test_logger.info("--- Fin de pruebas de utils.py ---")