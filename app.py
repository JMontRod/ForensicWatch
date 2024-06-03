import winreg
import datetime

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

def verificar_actividad_sospechosa(fecha_modificacion, umbral_dias=30):
    """
    Verifica si una modificación del registro es sospechosa.

    :param fecha_modificacion: Fecha de última modificación de la clave del registro.
    :param umbral_dias: Umbral en días para considerar la modificación como reciente.
    :return: True si la modificación es sospechosa, False en caso contrario.
    """
    ahora = datetime.datetime.now()
    diferencia = (ahora - fecha_modificacion).days
    
    return diferencia <= umbral_dias

def analizar_claves_relevantes():
    """
    Analiza las claves de registro más relevantes, muestra la fecha de última modificación y 
    verifica si las modificaciones pueden ser sospechosas.
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
        
        if fecha_modificacion:
            sospechoso = verificar_actividad_sospechosa(fecha_modificacion)
            estado = "Sospechoso" if sospechoso else "Normal"
            print(f"{descripcion} (Ruta: {clave_ruta}) - Última modificación: {fecha_modificacion} - {estado}")
        else:
            print(f"{descripcion} (Ruta: {clave_ruta}) - No se pudo obtener la fecha de modificación.")

if __name__ == "__main__":
    while True:
        realizar_busqueda = input("¿Deseas realizar una búsqueda de las claves del registro? (s/n): ").strip().lower()
        if realizar_busqueda in ['s', 'n']:
            break
        else:
            print("Entrada no válida. Por favor, ingresa 's' para sí o 'n' para no.")
    
    if realizar_busqueda == 's':
        analizar_claves_relevantes()
    else:
        print("Búsqueda cancelada.")