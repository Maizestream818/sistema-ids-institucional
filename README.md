# IDS Institucional

**IDS Institucional** es un Sistema de Detección de Intrusos (IDS) defensivo, desarrollado para monitorear y analizar el tráfico de red local en tiempo real. Su diseño modular le permite interceptar conexiones no autorizadas, registrar resolución de dominios y mitigar riesgos asociados a conexiones hacia direcciones IP con reputación maliciosa (Threat Intelligence).

El sistema se enfoca en la privacidad y legalidad, recolectando exclusivamente metadatos de red (MAC, IP, Dominio, Protocolo) sin inspeccionar el contenido cifrado (payloads) de las comunicaciones.

## Entorno de Ejecución Soportado

- **Sistema Operativo:** Ubuntu 24.04 LTS Desktop (o servidores Linux compatibles).
- **Entorno:** Red institucional física o máquina virtual configurada en modo puente (Bridged) para interceptación de red.

## Requisitos del Sistema

- Python 3.10 o superior.
- `pip` y `venv`.
- Librerías del sistema: `tcpdump`, `whois`, `net-tools`.
- Permisos de captura de paquetes a nivel de socket (cap_net_raw).
- Servidor SMTP (para notificación de alertas de emergencia).

## Instalación y Despliegue

1. **Instalación de dependencias del sistema:**
   ```bash
   sudo apt update
   sudo apt install -y python3 python3-pip python3-venv tcpdump whois net-tools
   ```

2. **Configuración del entorno virtual de Python:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

3. **Otorgar permisos de captura de red:**
   Para permitir que el sistema intercepte paquetes sin requerir usuario `root` para todo el intérprete:
   ```bash
   sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))
   ```

## Configuración del Entorno

El IDS requiere un archivo de variables de entorno para funcionar de manera segura sin exponer credenciales.

1. Navegue al directorio `config/` y cree el archivo `.env`:
   ```bash
   cp config/.env.example config/.env
   ```

2. Edite `config/.env` con las credenciales SMTP de envío y el correo del administrador receptor:
   ```env
   SMTP_SERVER=smtp.gmail.com
   SMTP_PORT=587
   SMTP_USER=alertas.ids@tudominio.com
   SMTP_PASSWORD=tu_app_password_segura
   ADMIN_EMAIL=administrador.seguridad@tudominio.com
   VIRUSTOTAL_API_KEY=tu_api_key_de_virustotal_opcional
   ```

## Administración de Reglas

Las políticas de acceso del IDS se controlan a través de archivos CSV en la carpeta `config/`.

- **Lista Blanca (Control de Acceso de Capa 2 y 3):** `config/whitelist.csv`  
  Contiene las direcciones IP y direcciones MAC de los dispositivos autorizados para operar en la red institucional.
- **Threat Intelligence (Lista Negra):** `config/blacklist_ips.csv`  
  Almacena el registro de IPs externas conocidas por comportamiento malicioso (Botnets, Malware, Phishing).

## Guía de Operación y Validación de Módulos

Para iniciar el sistema, active el entorno y ejecute el módulo principal:

```bash
source venv/bin/activate
sudo python3 src/main.py
```

El sistema desplegará un menú interactivo. A continuación se explica cómo el administrador puede validar el funcionamiento de los distintos módulos:

### 1. Módulo de Listas Blancas
El sistema inspecciona cada paquete ARP e IP. Si un dispositivo ajeno a `whitelist.csv` emite tráfico:
- **Validación:** Conecte un equipo no registrado a la red (o modifique la MAC de su equipo temporalmente). 
- **Resultado:** El IDS registrará la infracción en consola y disparará **inmediatamente un correo electrónico** al administrador alertando sobre el dispositivo no autorizado.

### 2. Módulo de Monitoreo de Sitios (DNS)
El IDS registra en tiempo real las resoluciones de dominio DNS para mantener una bitácora del tráfico web.
- **Validación:** Inicie el IDS (Opción 1) y en otra terminal realice un ping o consulta a un dominio (ej. `ping portal.azure.com`).
- **Resultado:** El dominio aparecerá en vivo en la consola y se almacenará permanentemente en `logs/site_report.log`. (Se puede visualizar con la Opción 3 del menú).

### 3. Módulo de IPs Peligrosas y Automatización Forense (Abuse/Whois)
El sistema compara las conexiones IP de salida contra su base de Threat Intelligence.
- **Validación:** Agregue una IP de prueba a `blacklist_ips.csv` e intente conectarse a ella mediante `curl` o `ping` desde un equipo de la red.
- **Resultado:** El IDS intercepta el tráfico, ejecuta automáticamente un análisis forense sobre la IP destino (extrayendo organización, país y contacto de *Abuse* vía comandos Whois) y la evalúa contra VirusTotal si está configurado. Se dispara automáticamente una **"Alerta de Emergencia"** por correo con el tipo de riesgo y los datos listos para reportar la incidencia.

### 4. Consultas VirusTotal Manuales
- **Validación:** Use la Opción 6 del menú principal para ingresar una IP pública.
- **Resultado:** El IDS se conecta vía API a VirusTotal para retornar la reputación del host bajo múltiples motores antivirus.

## Bitácoras y Auditoría (Logs)

Toda la actividad anómala detectada por el sistema se guarda para su posterior auditoría forense en el directorio `logs/`. Cada entrada es acompañada por una marca de tiempo (Timestamp):

- `unauthorized_devices.log`: Violaciones de Capa 2 y 3 (MAC/IP).
- `site_report.log`: Historial de consultas DNS.
- `threats_detected.log`: Intentos de conexión hacia la Lista Negra.
- `alerts.log`: Log general de funcionamiento y envíos SMTP.
