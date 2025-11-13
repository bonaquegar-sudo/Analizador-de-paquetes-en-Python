from scapy.all import sniff, IP, TCP, UDP
import tkinter as tk
from tkinter import scrolledtext
import threading
import time

# Variable global para controlar el estado de la captura
capturando = False

def procesar_paquete(paquete):
    """
    Función llamada por Scapy para analizar y mostrar cada paquete.
    """
    global output_area
    
    # Crea la línea de resumen que se mostrará en la GUI
    linea_resumen = "-----------------------------------------------------\n"
    linea_resumen += f"Paquete: {paquete.summary()}\n"
    
    if IP in paquete:
        capa_ip = paquete[IP]
        linea_resumen += f"  - IP Origen: {capa_ip.src}\n"
        linea_resumen += f"  - IP Destino: {capa_ip.dst}\n"
        
        if TCP in paquete:
            capa_tcp = paquete[TCP]
            linea_resumen += f"  - Protocolo: TCP\n"
            linea_resumen += f"    - Puerto Origen: {capa_tcp.sport}\n"
            linea_resumen += f"    - Puerto Destino: {capa_tcp.dport}\n"
            
        elif UDP in paquete:
            capa_udp = paquete[UDP]
            linea_resumen += f"  - Protocolo: UDP\n"
            linea_resumen += f"    - Puerto Origen: {capa_udp.sport}\n"
            linea_resumen += f"    - Puerto Destino: {capa_udp.dport}\n"
    
    # Insertar el texto en la caja de salida y hacer scroll al final
    output_area.insert(tk.END, linea_resumen)
    output_area.see(tk.END) # Asegura que la última línea sea visible

def iniciar_captura_thread():
    """
    Función que ejecuta Scapy en un hilo separado para no congelar la GUI.
    """
    global capturando
    
    # Obtiene el filtro escrito por el usuario
    filtro = filter_entry.get().strip()
    
    try:
        # Aquí se inicia la escucha de Scapy
        sniff(prn=procesar_paquete, store=0, stop_filter=lambda x: not capturando, filter=filtro)
    except Exception as e:
        # Manejo de errores de Scapy (ej. filtro incorrecto)
        output_area.insert(tk.END, f"\n--- ERROR DE CAPTURA ---\n{e}\n")
        output_area.see(tk.END)
        # Resetea el estado y la GUI en caso de error
        capturando = False
        start_button.config(text="Iniciar Captura", bg='lightgreen')
        
def manejar_captura():
    """
    Función que gestiona el clic del botón INICIAR/DETENER.
    """
    global capturando
    
    if not capturando:
        # INICIAR CAPTURA
        capturando = True
        output_area.insert(tk.END, f"\n--- INICIANDO CAPTURA (Filtro: '{filter_entry.get()}') ---\n")
        start_button.config(text="Detener Captura", bg='red')
        
        # Inicia la captura en un hilo de ejecución diferente
        # El hilo de ejecución (Thread) es CRUCIAL para que la GUI no se congele.
        hilo = threading.Thread(target=iniciar_captura_thread)
        hilo.start()
        
    else:
        # DETENER CAPTURA
        capturando = False
        start_button.config(text="Iniciando Cierre...", bg='orange')
        # Esperamos un momento para que el hilo de Scapy termine de forma segura
        root.after(500, lambda: start_button.config(text="Iniciar Captura", bg='lightgreen'))
        output_area.insert(tk.END, "\n--- CAPTURA DETENIDA ---\n")


# ----------------------------------------------------
# 3. Configuración de la Ventana Principal (Tkinter)
# ----------------------------------------------------

root = tk.Tk()
root.title("Analizador de Paquetes Scapy v1.0")
root.geometry("800x600")

# --- Filtro ---
tk.Label(root, text="Filtro (ej. tcp and port 80):").pack(pady=5)
filter_entry = tk.Entry(root, width=80)
filter_entry.insert(0, "") # Filtro por defecto (vacío = todo)
filter_entry.pack(pady=5)

# --- Botón ---
start_button = tk.Button(root, text="Iniciar Captura", command=manejar_captura, bg='lightgreen', width=20)
start_button.pack(pady=10)

# --- Área de Salida ---
# ScrolledText es un widget de texto con barra de desplazamiento automática
output_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=90, height=25)
output_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

# ----------------------------------------------------

# Iniciar el loop principal de Tkinter
root.mainloop()