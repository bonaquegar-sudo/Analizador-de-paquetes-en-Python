from scapy.all import sniff, IP, TCP, UDP
import tkinter as tk
from tkinter import scrolledtext
import threading
import time
import json 
import requests # Librería para llamadas HTTP a la API

# ----------------------------------------------------
# 0. CONFIGURACIÓN DE LA API (TU CLAVE)
# ----------------------------------------------------
API_KEY = "API_KEY_AQUI"  # Reemplaza con tu clave de OpenRouter.ai
MODELO = "tngtech/deepseek-r1t2-chimera:free"
API_URL = "https://openrouter.ai/api/v1/chat/completions"

# Variables globales para el control y el almacenamiento de datos
capturando = False
paquetes_capturados = [] # Lista para almacenar los diccionarios de paquetes

# ----------------------------------------------------
# 1. Lógica de Procesamiento y Almacenamiento
# ----------------------------------------------------

def procesar_paquete(paquete):
    """
    Función llamada por Scapy. Almacena los detalles en una lista.
    """
    global output_area, paquetes_capturados 
    
    # 1. Crear el diccionario para el paquete actual
    detalle_paquete = {
        # time.time() registra el momento, útil para el análisis cronológico
        "timestamp": time.time(), 
        "summary": paquete.summary(),
        "layer_ip": {},
        "layer_transport": {}
    }

    # 2. Rellenar los detalles IP
    if IP in paquete:
        capa_ip = paquete[IP]
        detalle_paquete["layer_ip"] = {
            "source": capa_ip.src,
            "destination": capa_ip.dst
        }
        
        # 3. Rellenar los detalles de Transporte (TCP/UDP)
        if TCP in paquete:
            capa_tcp = paquete[TCP]
            detalle_paquete["layer_transport"] = {
                "protocol": "TCP",
                "sport": capa_tcp.sport,
                "dport": capa_tcp.dport
            }
        elif UDP in paquete:
            capa_udp = paquete[UDP]
            detalle_paquete["layer_transport"] = {
                "protocol": "UDP",
                "sport": capa_udp.sport,
                "dport": capa_udp.dport
            }

    # 4. Añadir el diccionario a la lista global
    paquetes_capturados.append(detalle_paquete)
    
    # 5. Mostrar en la GUI
    linea_resumen = f"[{len(paquetes_capturados)}] {detalle_paquete.get('summary', 'Non-IP')}\n"
    output_area.insert(tk.END, linea_resumen)
    output_area.see(tk.END) # Scroll automático

# ----------------------------------------------------
# 2. Función de Resumen y Exportación (Integración con OpenRouter)
# ----------------------------------------------------

def generar_resumen_y_json():
    """
    Exporta los paquetes capturados a un JSON y llama a la API de OpenRouter
    para obtener un análisis.
    """
    global paquetes_capturados
    
    if not paquetes_capturados:
        output_area.insert(tk.END, "\n--- No hay paquetes capturados para resumir. ---\n")
        return

    # A. Generar el Archivo JSON
    json_data = json.dumps(paquetes_capturados, indent=4)
    
    nombre_archivo = f"paquetes_{int(time.time())}.json"
    try:
        with open(nombre_archivo, 'w') as f:
            f.write(json_data)
        output_area.insert(tk.END, f"\n✅ Datos Exportados a: {nombre_archivo}\n")
    except Exception as e:
        output_area.insert(tk.END, f"\n❌ Error al guardar JSON: {e}\n")


    # B. Generar Resumen con la API de OpenRouter (Llamada Real)
    
    num_paquetes = len(paquetes_capturados)
    output_area.insert(tk.END, f"\n🤖 Enviando {num_paquetes} paquetes para resumen a OpenRouter...\n")

    # 1. Definir el Prompt (Instrucción para la IA)
    prompt = (
        "Eres un analista de ciberseguridad. Analiza el siguiente tráfico de red, que está en formato JSON. "
        "Tu respuesta debe ser concisa, clara y NO DEBE incluir el JSON de entrada, solo el análisis. "
        "Identifica el tipo principal de actividad (navegación web, streaming, o algo sospechoso) y "
        "menciona las tres IP de destino más activas y sus puertos. El tráfico es el siguiente:\n\n"
        "Pon las cosas sin formato, recuerda que estas en una terminal, no uses markdown.\n\n"
        f"{json_data}"
    )

    # 2. Configurar la llamada API con tus credenciales
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json",
        # OpenRouter requiere el origen, aunque sea para un proyecto local
        "X-Title": "Python Sniffer Project" 
    }
    
    data = {
        "model": MODELO,
        "messages": [
            {"role": "user", "content": prompt}
        ]
    }

    # 3. Realizar la solicitud HTTP POST
    try:
        response = requests.post(API_URL, headers=headers, json=data, timeout=30) # Añadimos un timeout
        response.raise_for_status() # Lanza un error para códigos de estado 4xx/5xx

        # 4. Procesar la Respuesta
        response_data = response.json()
        
        # Acceder al contenido de la respuesta de la IA
        summary = response_data['choices'][0]['message']['content']

        output_area.insert(tk.END, "\n--- RESUMEN DE LA ACTIVIDAD DE RED (LongCat Flash Chat) ---\n")
        output_area.insert(tk.END, summary)
        
    except requests.exceptions.RequestException as e:
        output_area.insert(tk.END, f"\n❌ ERROR de Conexión o API: {e}\n")
        output_area.insert(tk.END, "Verifica tu clave API, el modelo y tu conexión a internet. También revisa la consola para ver el mensaje completo del error.")
        
    except (KeyError, IndexError):
        # Captura errores si la respuesta de la API no tiene el formato esperado
        output_area.insert(tk.END, f"\n❌ ERROR al procesar la respuesta de la IA. Mensaje completo:\n{response.text}\n")
        
    finally:
        # Limpiar la lista para la siguiente captura
        paquetes_capturados = [] 

# ----------------------------------------------------
# 3. Función de Control (Conexión al Resumen)
# ----------------------------------------------------

def iniciar_captura_thread():
    """
    Función que ejecuta Scapy en un hilo separado.
    """
    global capturando
    
    filtro = filter_entry.get().strip()
    
    try:
        # Aquí se inicia la escucha de Scapy
        sniff(prn=procesar_paquete, store=0, stop_filter=lambda x: not capturando, filter=filtro)
    except Exception as e:
        output_area.insert(tk.END, f"\n--- ERROR DE CAPTURA ---\n{e}\n")
        output_area.see(tk.END)
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
        # Limpiamos el área de texto para la nueva captura
        output_area.delete('1.0', tk.END) 
        output_area.insert(tk.END, f"\n--- INICIANDO CAPTURA (Filtro: '{filter_entry.get()}') ---\n")
        start_button.config(text="Detener Captura", bg='red')
        
        # Inicia la captura en un hilo de ejecución diferente
        hilo = threading.Thread(target=iniciar_captura_thread)
        hilo.start()
        
    else:
        # DETENER CAPTURA
        capturando = False
        start_button.config(text="Iniciando Cierre...", bg='orange')
        
        output_area.insert(tk.END, "\n--- CAPTURA DETENIDA ---\n")
        
        # ⬅️ LLAMADA A LA FUNCIÓN DE RESUMEN
        # Esperamos un momento para que el hilo de Scapy termine y luego resumimos.
        root.after(500, generar_resumen_y_json)
        
        # Resetea el botón de la GUI
        root.after(500, lambda: start_button.config(text="Iniciar Captura", bg='lightgreen'))

# ----------------------------------------------------
# 4. Configuración de la Ventana Principal
# ----------------------------------------------------

root = tk.Tk()
root.title("Analizador de Paquetes Scapy con IA v2.0")
root.geometry("800x600")

# --- Filtro ---
tk.Label(root, text="Filtro (ej. tcp and port 80):").pack(pady=5)
filter_entry = tk.Entry(root, width=80)
filter_entry.insert(0, "tcp and port 443") # Filtro por defecto: solo tráfico HTTPS
filter_entry.pack(pady=5)

# --- Botón ---
start_button = tk.Button(root, text="Iniciar Captura", command=manejar_captura, bg='lightgreen', width=20)
start_button.pack(pady=10)

# --- Área de Salida ---
output_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=90, height=25)
output_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

# ----------------------------------------------------

root.mainloop()