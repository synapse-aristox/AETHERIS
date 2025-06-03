# tests/test_utils.py

# --- Bloque de Verificación e Instalación de Dependencias ---
try:
    import pytest
except ImportError:
    print("\n[!] 'pytest' no encontrado. Por favor, instálalo para ejecutar los tests.")
    print("    Puedes hacerlo ejecutando: pip install pytest")
    print("    Saliendo de la ejecución de tests.")
    exit(1) # Salir con un código de error

# Dependencia opcional para slugify (manejo de acentos)
try:
    import unidecode
except ImportError:
    print("[!] 'unidecode' no encontrado. 'slugify' funcionará, pero no normalizará caracteres acentuados.")
    print("    Si deseas esta funcionalidad, instálalo con: pip install unidecode")
    # No salimos, ya que es una dependencia opcional para un solo test.


# --- Fin del Bloque de Verificación de Dependencias ---


# Importaciones necesarias para los tests
import os
import shutil
import datetime
from aetheris.lib import utils # Importamos el módulo utils


# --- Tests para validate_ip ---
def test_validate_ip_valid():
    """Debe validar IPs IPv4 válidas."""
    assert utils.validate_ip("192.168.1.1") is True
    assert utils.validate_ip("10.0.0.255") is True
    assert utils.validate_ip("0.0.0.0") is True
    assert utils.validate_ip("255.255.255.255") is True

def test_validate_ip_invalid_format():
    """Debe invalidar IPs con formato incorrecto."""
    assert utils.validate_ip("256.0.0.1") is False  # Octeto fuera de rango
    assert utils.validate_ip("192.168.1") is False  # Faltan octetos
    assert utils.validate_ip("192.168.1.1.1") is False # Sobran octetos
    assert utils.validate_ip("abc.def.g.h") is False # Caracteres no numéricos
    assert utils.validate_ip("192.168.1.1 ") is False # Espacio al final
    assert utils.validate_ip(" 192.168.1.1") is False # Espacio al inicio
    assert utils.validate_ip("") is False
    assert utils.validate_ip(None) is False # Prueba con None

def test_validate_ip_mixed_types():
    """Debe invalidar entradas que no sean cadenas."""
    assert utils.validate_ip(12345) is False
    assert utils.validate_ip(["192.168.1.1"]) is False

# --- Tests para validate_port ---
def test_validate_port_valid():
    """Debe validar puertos en el rango 1-65535."""
    assert utils.validate_port(1) is True
    assert utils.validate_port(80) is True
    assert utils.validate_port(65535) is True
    assert utils.validate_port("22") is True # Prueba con string

def test_validate_port_invalid():
    """Debe invalidar puertos fuera del rango o con formato incorrecto."""
    assert utils.validate_port(0) is False
    assert utils.validate_port(65536) is False
    assert utils.validate_port(-1) is False
    assert utils.validate_port("abc") is False
    assert utils.validate_port("") is False
    assert utils.validate_port(None) is False

# --- Tests para validate_subnet ---
def test_validate_subnet_valid():
    """Debe validar subredes CIDR IPv4 válidas."""
    assert utils.validate_subnet("192.168.1.0/24") is True
    assert utils.validate_subnet("10.0.0.0/8") is True
    assert utils.validate_subnet("172.16.0.0/16") is True
    assert utils.validate_subnet("192.168.1.1/32") is True # Single host CIDR
    assert utils.validate_subnet("0.0.0.0/0") is True # Default route

def test_validate_subnet_invalid():
    """Debe invalidar subredes CIDR IPv4 inválidas."""
    assert utils.validate_subnet("192.168.1.0/33") is False # Máscara inválida
    assert utils.validate_subnet("192.168.1.0/foo") is False # Máscara no numérica
    assert utils.validate_subnet("invalid_cidr") is False
    assert utils.validate_subnet("1.2.3") is False # No es CIDR
    assert utils.validate_subnet("") is False
    assert utils.validate_subnet(None) is False

# --- Tests para get_timestamp ---
def test_get_timestamp_format():
    """Debe devolver un timestamp en el formato esperado (YYYYMMDD_HHMMSS)."""
    timestamp = utils.get_timestamp()
    assert isinstance(timestamp, str)
    # Validar longitud y formato básico (ej. 20240101_123456)
    assert len(timestamp) == 15
    assert timestamp[8] == '_'
    assert timestamp.isdigit() or (timestamp[:8].isdigit() and timestamp[9:].isdigit())

    # Asegurarse de que el timestamp cambie con el tiempo (pequeña diferencia)
    import time
    time.sleep(0.01) # Esperar un poco para asegurar un timestamp diferente
    assert utils.get_timestamp() != timestamp

# --- Tests para ensure_directory ---
def test_ensure_directory_creates_new_dir(tmp_path):
    """Debe crear un directorio si no existe."""
    new_dir = tmp_path / "test_new_dir"
    assert not new_dir.exists()
    utils.ensure_directory(str(new_dir))
    assert new_dir.is_dir()

def test_ensure_directory_does_nothing_if_exists(tmp_path):
    """No debe fallar si el directorio ya existe."""
    existing_dir = tmp_path / "test_existing_dir"
    existing_dir.mkdir()
    assert existing_dir.is_dir()
    # No debería levantar excepción
    utils.ensure_directory(str(existing_dir))
    assert existing_dir.is_dir() # Sigue existiendo

def test_ensure_directory_creates_nested_dirs(tmp_path):
    """Debe crear directorios anidados si no existen."""
    nested_dir = tmp_path / "level1" / "level2" / "level3"
    assert not nested_dir.exists()
    utils.ensure_directory(str(nested_dir))
    assert nested_dir.is_dir()

# --- Tests para slugify ---
def test_slugify_basic():
    """Debe convertir texto básico a slug."""
    assert utils.slugify("Hello World") == "hello-world"
    assert utils.slugify("My File.txt") == "my-file-txt"
    assert utils.slugify("Another Example") == "another-example"

def test_slugify_special_characters():
    """Debe manejar caracteres especiales y múltiples espacios."""
    assert utils.slugify("File Name with !@#$%^&*()_+={}|[]\\:;\"'<>,.?/~`") == "file-name-with"
    assert utils.slugify("  Leading and Trailing Spaces  ") == "leading-and-trailing-spaces"
    assert utils.slugify("Multiple   Spaces   Here") == "multiple-spaces-here"
    assert utils.slugify("Dash-Already-Exists") == "dash-already-exists"
    assert utils.slugify("Underscore_Is_Replaced") == "underscore-is-replaced"

def test_slugify_empty_string():
    """Debe manejar cadenas vacías."""
    assert utils.slugify("") == ""
    assert utils.slugify("   ") == ""

@pytest.mark.skipif(unidecode is None, reason="unidecode library not installed")
def test_slugify_accented_characters_with_unidecode():
    """Debe normalizar caracteres acentuados si unidecode está instalado."""
    assert utils.slugify("Servidor Núcleo (áéíóúñ)") == "servidor-nucleo-aeioun"
    assert utils.slugify("São Paulo") == "sao-paulo"
    assert utils.slugify("résumé") == "resume"

@pytest.mark.skipif(unidecode is not None, reason="unidecode library is installed")
def test_slugify_accented_characters_without_unidecode():
    """Debe manejar (posiblemente eliminar) caracteres acentuados si unidecode NO está instalado."""
    # El comportamiento sin unidecode es que los caracteres no alfanuméricos se eliminan.
    assert utils.slugify("Servidor Núcleo (áéíóúñ)") == "servidor-ncleo"
    assert utils.slugify("São Paulo") == "sao-paulo" # 'o' en Sao es ya ASCII
    assert utils.slugify("résumé") == "resume" # 'e' es ascii, 's' se mantiene


# --- Tests para extract_target_ip_from_path ---
def test_extract_target_ip_from_path_valid():
    """Debe extraer IPs válidas de rutas de resultados."""
    path1 = "resultados/192.168.1.100_20240602_150000/nmap.xml"
    path2 = "some/other/path/10.0.0.1_timestamp/report.html"
    path3 = "/tmp/scans/172.16.2.3_latest/data.json"
    assert utils.extract_target_ip_from_path(path1) == "192.168.1.100"
    assert utils.extract_target_ip_from_path(path2) == "10.0.0.1"
    assert utils.extract_target_ip_from_path(path3) == "172.16.2.3"

def test_extract_target_ip_from_path_invalid_ip():
    """Debe devolver 'Unknown' para IPs inválidas o formato incorrecto."""
    path1 = "resultados/256.0.0.1_20240602_150000/nmap.xml" # IP inválida
    path2 = "results/not_an_ip_20240602_160000/" # No es una IP
    path3 = "just_a_folder/nmap.xml" # Sin IP_timestamp
    assert utils.extract_target_ip_from_path(path1) == "Unknown"
    assert utils.extract_target_ip_from_path(path2) == "Unknown"
    assert utils.extract_target_ip_from_path(path3) == "Unknown"
    assert utils.extract_target_ip_from_path("") == "Unknown"
    assert utils.extract_target_ip_from_path(None) == "Unknown"