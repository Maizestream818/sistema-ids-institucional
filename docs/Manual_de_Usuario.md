# Manual de Usuario - IDS Institucional

Bienvenido al Manual de Usuario del **IDS Institucional**. Este documento está diseñado para guiarte en la instalación, configuración, operación y solución de problemas del sistema, sin necesidad de recurrir al desarrollador.

---

## 1. Guía de Instalación y Requisitos

### Sistema Operativo Recomendado
El sistema ha sido diseñado y probado para funcionar óptimamente en entornos Linux.
- **Recomendado:** Ubuntu 24.04 LTS Desktop (Ejecución dentro de una máquina virtual de laboratorio).

### Prerrequisitos del Sistema
Antes de comenzar, asegúrate de contar con los siguientes elementos instalados en tu sistema:
- **Python 3**, **pip** y **venv** (para la gestión de paquetes y entornos virtuales).
- **Librerías de captura de paquetes:** Se requiere Libpcap (en sistemas Linux se instala a través de `tcpdump` o se usa internamente por herramientas de red).
- **Herramientas de red de Linux:** `tcpdump`, `whois`, y `net-tools`.
- **Permisos de administrador (sudo/root):** Necesarios para poner la tarjeta de red en modo de captura de paquetes.

### Instrucciones de Instalación
Abre una terminal y ejecuta los siguientes comandos para instalar todas las dependencias del sistema operativo:

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv tcpdump whois net-tools
```

Posteriormente, descarga o clona el repositorio del proyecto, entra a la carpeta, crea el entorno virtual e instala las dependencias de Python (como `scapy`, `requests`, etc.):

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Para permitir que el script capture tráfico sin necesidad de ser root explícitamente en cada ejecución, asigna los permisos correspondientes:
```bash
sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))
```

### Configuración del Servidor SMTP para Correo de Alertas
El IDS enviará reportes y alertas a tu correo. Para habilitarlo, debes configurar las credenciales SMTP.

1. Navega a la carpeta `config/` dentro del proyecto.
2. Copia el archivo de ejemplo: `cp .env.example .env` (o crea un archivo `.env` manualmente).
3. Abre `.env` con un editor de texto e ingresa tus datos (recomendado usar correos de Gmail con "App Passwords"):

```env
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=tu_correo_que_envia@gmail.com
SMTP_PASSWORD=tu_app_password_generada
ADMIN_EMAIL=correo_destino_alertas@example.com
VIRUSTOTAL_API_KEY=tu_api_key_opcional
```

---

## 2. Instrucciones de Operación

Una vez instalado y configurado el sistema, inicia el IDS ejecutando desde la raíz del proyecto:
```bash
source venv/bin/activate
sudo python3 src/main.py
```

A continuación, se detalla paso a paso cómo utilizar las funciones principales del sistema.

### 2.1 Dar de alta una IP/MAC en la Lista Blanca

Al iniciar el programa, verás el **Menú Principal**. 

> 🛑 **¡ATENCIÓN! ACCIÓN REQUERIDA (1/3)**  
> **[AQUÍ DEBES INSERTAR UNA CAPTURA DE PANTALLA MOSTRANDO EL MENÚ PRINCIPAL DEL SISTEMA]**  
> *Ejemplo de texto sugerido para la captura: La terminal mostrando las opciones del 1 al 7.*

1. Ingresa la opción **2** ("Gestionar lista blanca") y presiona Enter.
2. El sistema mostrará la lista actual de dispositivos autorizados.
3. Elige la opción para **Agregar dispositivo**.
4. Ingresa la IP del dispositivo.
5. Ingresa la dirección MAC.
6. Ingresa una breve descripción (ej. "Laptop del laboratorio").

> 🛑 **¡ATENCIÓN! ACCIÓN REQUERIDA (2/3)**  
> **[AQUÍ DEBES INSERTAR UNA CAPTURA DE PANTALLA MOSTRANDO EL PROCESO DE AGREGAR UN DISPOSITIVO (IP, MAC y Descripción)]**

Al completar estos pasos, el dispositivo quedará autorizado y sus conexiones no generarán alertas de intrusión.

### 2.2 Ver el reporte del sistema (Sitios y Alertas)

Puedes verificar qué sitios web han sido visitados o qué alertas se han generado durante la sesión de monitoreo usando las opciones del menú:

- **Opción 3 ("Ver reporte de sitios visitados"):** Te mostrará en pantalla todos los dominios DNS que han sido consultados por los equipos de la red.
- **Opción 4 ("Ver alertas generadas"):** Imprimirá en consola el historial de advertencias detectadas.

> 🛑 **¡ATENCIÓN! ACCIÓN REQUERIDA (3/3)**  
> **[AQUÍ DEBES INSERTAR UNA CAPTURA DE PANTALLA MOSTRANDO LA SALIDA DE LA OPCIÓN 3 O 4, CON LA TABLA DE REPORTES EN CONSOLA]**

### 2.3 Cómo interpretar las alertas y el reporte

Las alertas generadas por el sistema (que también llegan por correo) o los logs guardados en `logs/alerts.log` contienen metadatos importantes. No se capturan contraseñas ni el contenido de las páginas web (HTTP content), solo metadatos.

- **IP Origen:** Qué computadora de tu red intentó hacer la conexión.
- **IP Destino:** Hacia dónde se intentó conectar (puede ser un dominio externo).
- **Tipo de Riesgo (Risk Type):** Qué regla rompió el paquete (ej. "Dispositivo no autorizado", "Conexión a IP peligrosa").
- **Descripción:** Detalles adicionales (ej. país de destino u organización).

**Niveles de riesgo interpretables:**
- Si ves alertas relacionadas con **"IPs Peligrosas"** significa que un equipo intentó contactar un servidor catalogado en el archivo `blacklist_ips.csv`.
- Si ves alertas de **"Dispositivo no autorizado"**, significa que hay una máquina física en el switch o red Wi-Fi que no ha sido dada de alta en la lista blanca (Sección 2.1).

---

## 3. Troubleshooting Básico (Resolución de Problemas)

Si encuentras dificultades al ejecutar el IDS, revisa la siguiente lista de errores comunes y sus respectivas soluciones.

### 3.1 Errores Comunes

| Error / Síntoma | Posible Causa | Solución |
| :--- | :--- | :--- |
| **Error: "Operation not permitted"** o "Permiso denegado al iniciar scapy" | El script no tiene permisos para capturar paquetes en la tarjeta de red. | Ejecuta el script con permisos de superusuario: `sudo python3 src/main.py` o vuelve a ejecutar el comando `sudo setcap ...` indicado en instalación. |
| **No se detectan alertas en absoluto** | Estás monitoreando la interfaz de red incorrecta (ej. `eth0` en vez de `wlan0`). | Al iniciar el monitoreo (Opción 1), escribe explícitamente el nombre de tu interfaz de red en lugar de dejar que el sistema lo autodetecte. Usa `ip link` para ver tus interfaces. |
| **No se captura tráfico de otras máquinas** | La red es switcheada y el modo promiscuo no es suficiente, o la VM está en modo NAT. | Cambia la tarjeta de red de tu Máquina Virtual a "Adaptador Puente" (Bridged) para que pueda ver el tráfico real del laboratorio. |
| **Falla al buscar en VirusTotal (Opción 6)** | Falta la API Key en el archivo `.env` o el límite gratuito fue excedido. | Verifica que `VIRUSTOTAL_API_KEY` tenga un valor válido en tu `.env`. La API gratuita tiene un límite de consultas por minuto. |

### 3.2 ¿Qué hacer si el correo de alerta no llega o se va a SPAM?

Es muy común que los servicios de correo electrónico (Gmail, Outlook, Yahoo) clasifiquen los reportes generados automáticamente por scripts de Python como "Correo no deseado" (Spam) debido a que no proceden de un servidor de correo tradicional de confianza.

**Si no ves el correo en tu bandeja de entrada:**
1. Ve a la carpeta de **Spam** o **Correo no deseado**.
2. Busca el mensaje (el asunto suele ser `[IDS ALERTA]` o similar).
3. Selecciona el mensaje y haz clic en el botón **"Informar que no es spam"** o **"No es correo no deseado"**.
4. **Agregar a Lista Blanca:** Añade la dirección de correo configurada en `SMTP_USER` a tu libreta de contactos. Esto entrenará al filtro antispam para confiar en el remitente en futuras ocasiones.
5. **Verificar `.env`:** Si el correo no está ni en la bandeja de entrada ni en Spam, asegúrate de que el usuario, el App Password y los puertos SMTP (generalmente `587`) en `config/.env` son correctos y de que tienes conexión a internet al enviar el reporte.
