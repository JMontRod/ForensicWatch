import winreg
import datetime
import hashlib
import os
import ctypes

def obtener_fecha_modificacion(clave_ruta):
    """
    Obtiene la fecha de la última modificación de una clave del registro de Windows.

    :param clave_ruta: Ruta completa de la clave del registro.
    :return: Fecha de última modificación en un formato legible o None si ocurre un error.
    """
    try:
        # Abre la clave del registro en modo solo lectura
        clave = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, clave_ruta, 0, winreg.KEY_READ)
        
        # Obtiene información sobre la clave, incluyendo la fecha de la última modificación
        info_clave = winreg.QueryInfoKey(clave)
        fecha_modificacion = info_clave[2]  # Índice 2 contiene el timestamp de modificación
        
        # Convierte el timestamp del registro a una fecha legible
        fecha_modificacion = datetime.datetime.fromtimestamp(fecha_modificacion / 10**7 - 11644473600)
        
        # Cierra la clave del registro
        winreg.CloseKey(clave)
        
        return fecha_modificacion
    except WindowsError as e:
        print(f"Error al acceder a la clave del registro: {e}")
        return None

def verificar_actividad_sospechosa(fecha_modificacion, umbral_dias=5):
    """
    Verifica si una modificación del registro es sospechosa.

    :param fecha_modificacion: Fecha de última modificación de la clave del registro.
    :param umbral_dias: Umbral en días para considerar la modificación como reciente.
    :return: True si la modificación es sospechosa, False en caso contrario.
    """
    ahora = datetime.datetime.now()
    diferencia = (ahora - fecha_modificacion).days
    
    return diferencia <= umbral_dias

def calcular_hash_clave(clave_ruta):
    """
    Calcula el hash SHA-256 de una clave del registro de Windows.

    :param clave_ruta: Ruta completa de la clave del registro.
    :return: Hash SHA-256 de la clave o None si ocurre un error.
    """
    try:
        # Abre la clave del registro en modo solo lectura
        clave = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, clave_ruta, 0, winreg.KEY_READ)
        
        # Lee todas las subclaves y valores
        hash_obj = hashlib.sha256()
        i = 0
        while True:
            try:
                nombre_subclave = winreg.EnumKey(clave, i)
                hash_obj.update(nombre_subclave.encode('utf-8'))
                i += 1
            except OSError:
                break
        
        i = 0
        while True:
            try:
                nombre_valor, valor, tipo = winreg.EnumValue(clave, i)
                hash_obj.update(nombre_valor.encode('utf-8'))
                hash_obj.update(str(valor).encode('utf-8'))
                i += 1
            except OSError:
                break
        
        # Cierra la clave del registro
        winreg.CloseKey(clave)
        
        return hash_obj.hexdigest()
    except WindowsError as e:
        print(f"Error al acceder a la clave del registro: {e}")
        return None

def detectar_archivos_ocultos(directorio):
    """
    Detecta archivos ocultos en un directorio.

    :param directorio: Ruta del directorio a escanear.
    """
    try:
        for root, dirs, files in os.walk(directorio):
            for nombre in files + dirs:
                ruta = os.path.join(root, nombre)
                atributos = ctypes.windll.kernel32.GetFileAttributesW(ruta)
                if atributos == -1:
                    raise ctypes.WinError()
                if atributos & 0x02:  # FILE_ATTRIBUTE_HIDDEN
                    print(f"Archivo oculto detectado: {ruta}")
    except Exception as e:
        print(f"Error al escanear el directorio {directorio}: {e}")

def verificar_eliminacion_logs(logs):
    """
    Verifica si los logs especificados han sido eliminados o modificados.

    :param logs: Lista de rutas de logs a verificar.
    """
    for log in logs:
        if not os.path.exists(log):
            print(f"Log eliminado o no encontrado: {log}")
        else:
            print(f"Log presente: {log}")

def analizar_claves_relevantes(verificar_hashes=False, hashes_conocidos=None):
    """
    Analiza las claves de registro más relevantes, muestra la fecha de última modificación y 
    verifica si las modificaciones pueden ser sospechosas. También puede verificar los hashes
    de las claves si se solicita.

    :param verificar_hashes: Booleano para indicar si se deben verificar los hashes.
    :param hashes_conocidos: Diccionario con los hashes conocidos de las claves.
    """
    claves_relevantes = {
        "Información del sistema": r"SYSTEM\CurrentControlSet\Control\Session Manager",
        "Programas instalados": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "Servicios del sistema": r"SYSTEM\CurrentControlSet\Services",
        "Ejecutables al inicio": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "Controladores de hardware": r"SYSTEM\CurrentControlSet\Enum",
        "Políticas de grupo": r"SOFTWARE\Policies\Microsoft\Windows",
        "Configuración de red": r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
        "Usuarios del sistema": r"SAM\SAM\Domains\Account\Users",
        "Historial de eventos": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs",
    }
    
    for descripcion, clave_ruta in claves_relevantes.items():
        fecha_modificacion = obtener_fecha_modificacion(clave_ruta)
        hash_actual = calcular_hash_clave(clave_ruta) if verificar_hashes else None
        
        if fecha_modificacion:
            sospechoso = verificar_actividad_sospechosa(fecha_modificacion)
            estado = "Sospechoso" if sospechoso else "Normal"
            print(f"{descripcion} (Ruta: {clave_ruta}) - Última modificación: {fecha_modificacion} - {estado}- Hash: {hash_actual}")
            
            if verificar_hashes and hashes_conocidos:
                hash_conocido = hashes_conocidos.get(descripcion)
                if hash_actual:
                    if hash_conocido and hash_actual != hash_conocido:
                        print(f"  - Hash cambiado: {hash_actual} (conocido: {hash_conocido})")
                    else:
                        print(f"  - Hash actual: {hash_actual}")
        else:
            print(f"{descripcion} (Ruta: {clave_ruta}) - No se pudo obtener la fecha de modificación.")
            if verificar_hashes:
                print(f"  - No se pudo calcular el hash.")

def mostrar_menu():
    """
    Este es el menú con las opciones disponibles para ejecutar.
    """
    print("\nOpciones disponibles:")
    print("1. Analizar claves del registro")
    print("2. Detectar archivos ocultos")
    print("3. Verificar eliminación de logs")
    print("4. Salir")
    return input("\nSeleccione una opción: ").strip()

def main():
    """
    Función principal que gestiona la ejecución del script.
    """
    while True:
        opcion = mostrar_menu()
        if opcion == '1':
            # No se pregunta por los hashes conocidos, simplemente se pasa None
            hashes_conocidos = None
            analizar_claves_relevantes(verificar_hashes=True, hashes_conocidos=hashes_conocidos)
            break
        elif opcion == '2':
            directorios_archivos_ocultos = [
                # Añade aquí las rutas de los directorios que deseas escanear
                r"C:\Users\example\Desktop",
                r"C:\Ruta\Al\Directorio2",
                # ...
            ]
            for directorio in directorios_archivos_ocultos:
                detectar_archivos_ocultos(directorio)
            break
        elif opcion == '3':
            rutas_logs = [
                # Añade aquí las rutas de los logs que deseas verificar
                r"C:\Windows\System32\winevt\Logs\Security.evtx",
                r"C:\Windows\System32\winevt\Logs\Application.evtx",
                # ...
            ]
            verificar_eliminacion_logs(rutas_logs)
            break
        elif opcion == '4':
            print("Saliendo...")
            break
        
        else:
            print("Opción no válida, por favor seleccione una opción válida.")

if __name__ == "__main__":
    main()



        
