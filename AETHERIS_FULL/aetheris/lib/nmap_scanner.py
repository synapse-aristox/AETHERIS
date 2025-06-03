# AETHERIS_FULL/lib/nmap_scanner.py

import subprocess
import os
import shutil # Necesario para el bloque de pruebas (__main__)
from .utils import setup_logging

# Importa el módulo utils y sus componentes específicos
# Aquí, importamos el logger directamente y las funciones que usaremos con el prefijo 'utils.'
from .utils import aetheris_logger as logger, ensure_directory, get_timestamp, slugify

def run_nmap_scan(target: str, output_dir: str, nmap_options: str = "-sV -O -Pn --max-retries 2 --host-timeout 30m") -> str | None:
    """
    Ejecuta un escaneo Nmap en el objetivo especificado y guarda la salida XML.

    Args:
        target (str): La dirección IP o rango CIDR a escanear.
        output_dir (str): El directorio donde se guardarán los resultados del escaneo.
        nmap_options (str): Cadena de opciones de Nmap. Por defecto, usa opciones comunes.

    Returns:
        str or None: La ruta completa al archivo XML de Nmap si el escaneo fue exitoso,
                     None en caso contrario.
    """
    # Asegurarse de que el directorio de salida exista
    ensure_directory(output_dir)

    # Generar un nombre de archivo seguro para la salida XML
    timestamp = get_timestamp()
    output_filename = f"{slugify(target)}_{timestamp}_nmap.xml"
    output_filepath = os.path.join(output_dir, output_filename)

    # Construir el comando Nmap
    # Dividimos las opciones de Nmap por espacios para pasarlas como lista a subprocess.run
    options_list = nmap_options.split()
    
    nmap_command = [
        "nmap",
        *options_list,  # Desempaqueta la lista de opciones
        "-oX", output_filepath, # Salida XML al archivo especificado
        target          # El objetivo de escaneo (IP o rango CIDR)
    ]

    logger.info(f"Iniciando escaneo Nmap para el objetivo: {target}")
    logger.info(f"Comando Nmap: {' '.join(nmap_command)}")
    logger.info(f"Guardando salida XML en: {output_filepath}")

    try:
        # Ejecutar el comando Nmap
        # capture_output=True captura stdout y stderr
        # text=True decodifica la salida como texto
        # check=True lanzará CalledProcessError si el comando retorna un código de salida no cero
        process = subprocess.run(
            nmap_command,
            capture_output=True,
            text=True,
            check=True,
            encoding='utf-8', # Asegurar la codificación correcta
            errors='replace' # Reemplazar caracteres que no pueden ser decodificados
        )
        logger.info(f"Escaneo Nmap completado para {target}. Salida XML guardada.")
        if process.stdout:
            logger.debug(f"Nmap stdout:\n{process.stdout}")
        if process.stderr:
            logger.debug(f"Nmap stderr:\n{process.stderr}")
        
        return output_filepath

    except FileNotFoundError:
        logger.error("Error: 'nmap' no se encontró. Asegúrate de que Nmap esté instalado y en tu PATH.")
        return None
    except subprocess.CalledProcessError as e:
        logger.error(f"Error al ejecutar Nmap para {target}:")
        logger.error(f"  Código de salida: {e.returncode}")
        logger.error(f"  Stdout: {e.stdout.strip()}")
        logger.error(f"  Stderr: {e.stderr.strip()}")
        # Nmap a menudo retorna 1 si no encuentra hosts, lo cual no siempre es un error grave.
        # Puedes añadir lógica aquí para diferenciar errores críticos de advertencias de Nmap,
        # pero por ahora, cualquier error de Nmap será reportado como ERROR y detendrá el proceso.
        return None
    except Exception as e:
        logger.error(f"Ocurrió un error inesperado al ejecutar Nmap: {e}")
        return None

# --- Bloque para pruebas rápidas (opcional) ---
if __name__ == "__main__":
    # Configurar un logger básico para las pruebas del módulo nmap_scanner.py
    # Normalmente, setup_logging se llamaría una vez en aetheris_main.py
    # Aquí usamos directamente el logger ya importado 'logger' (que es aetheris_logger)
    # pero para que funcione standalone, simulamos su configuración o usamos un logger simple.
    # Para la prueba, reconfiguramos el logger para que imprima en consola si no está ya configurado.
    if not logger.handlers: # Si el logger no tiene handlers (no ha sido configurado por aetheris_main)
        setup_logging(log_level='DEBUG') # DEBUG para ver más detalle

    logger.info("\n--- Probando nmap_scanner.py ---")
    
    # Define un directorio temporal para guardar los resultados de la prueba
    temp_test_output_dir = "temp_nmap_results"
    
    # Asegúrate de limpiar cualquier directorio de prueba anterior
    if os.path.exists(temp_test_output_dir):
        shutil.rmtree(temp_test_output_dir)
        logger.info(f"Directorio de prueba '{temp_test_output_dir}' limpiado.")

    ensure_directory(temp_test_output_dir)
    logger.info(f"Directorio de prueba creado: {temp_test_output_dir}")

    # --- Caso de prueba 1: Escaneo a localhost (127.0.0.1) ---
    logger.info("\n--- Ejecutando escaneo a 127.0.0.1 con opciones por defecto ---")
    nmap_xml_path_1 = run_nmap_scan("127.0.0.1", temp_test_output_dir)
    if nmap_xml_path_1:
        logger.info(f"Escaneo a 127.0.0.1 completado. XML en: {nmap_xml_path_1}")
        if os.path.exists(nmap_xml_path_1):
            logger.info(f"Tamaño del archivo XML: {os.path.getsize(nmap_xml_path_1)} bytes")
        else:
            logger.error("¡Advertencia! El archivo XML no se encontró después del escaneo exitoso reportado.")
    else:
        logger.error("El escaneo a 127.0.0.1 falló.")

    # --- Caso de prueba 2: Escaneo con opciones personalizadas (ejemplo) ---
    logger.info("\n--- Ejecutando escaneo a 127.0.0.1 con opciones personalizadas (-F -sV) ---")
    custom_options = "-F -sV" # Escaneo rápido y detección de versión
    nmap_xml_path_custom = run_nmap_scan("127.0.0.1", temp_test_output_dir, custom_options)
    if nmap_xml_path_custom:
        logger.info(f"Escaneo a 127.0.0.1 con opciones personalizadas completado. XML en: {nmap_xml_path_custom}")
    else:
        logger.error("El escaneo a 127.0.0.1 con opciones personalizadas falló.")

    # --- Caso de prueba 3: Objetivo que probablemente no existe (para ver manejo de errores) ---
    # Nota: Nmap puede tardar en responder para un objetivo que no existe.
    # Considera descomentar esta prueba si no quieres esperar.
    # logger.info("\n--- Ejecutando escaneo a una IP inexistente (ej. 192.0.2.1 - rango de documentación) ---")
    # nmap_xml_path_2 = run_nmap_scan("192.0.2.1", temp_test_output_dir)
    # if nmap_xml_path_2:
    #     logger.info(f"Escaneo a 192.0.2.1 completado. XML en: {nmap_xml_path_2}")
    # else:
    #     logger.error("El escaneo a 192.0.2.1 falló (comportamiento esperado si no hay hosts).")


    # --- Limpieza del directorio de prueba ---
    logger.info(f"\nLimpiando directorio de prueba: {temp_test_output_dir}")
    if os.path.exists(temp_test_output_dir):
        shutil.rmtree(temp_test_output_dir)
        logger.info(f"Directorio '{temp_test_output_dir}' eliminado.")
    
    logger.info("--- Fin de pruebas de nmap_scanner.py ---")