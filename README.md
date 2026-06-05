# IDS Institucional

IDS Institucional es un sistema IDS defensivo por consola para una practica universitaria. Esta diseñado para ejecutarse en Ubuntu 24.04 LTS Desktop dentro de una maquina virtual y monitorear una red de laboratorio propia o autorizada.

El sistema solo registra metadatos necesarios para bitacoras y alertas: IP, MAC, dominio DNS, hora, tipo de alerta y riesgo. No captura contrasenas, cookies, contenido HTTP ni informacion personal innecesaria.

## Sistema operativo recomendado

- Ubuntu 24.04 LTS Desktop.
- Ejecucion dentro de una maquina virtual de laboratorio.
- Red propia, institucional autorizada o ambiente controlado por el estudiante/docente.

## Requisitos

- Python 3.
- pip.
- venv.
- tcpdump.
- whois.
- net-tools.
- Permisos para captura de paquetes.
- Cuenta SMTP para envio de alertas.

## Instalacion en Ubuntu 24.04 LTS

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv tcpdump whois net-tools
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))
sudo python3 src/main.py
```

> Nota: si usas entorno virtual, activa `venv` antes de instalar dependencias. En algunos entornos educativos puede ser mas simple ejecutar el IDS con `sudo python3 src/main.py`.

## Configuracion

1. Copia el archivo de ejemplo:

```bash
cp config/.env.example config/.env
```

2. Edita `config/.env` con los datos SMTP reales:

```env
SMTP_SERVER=smtp.example.com
SMTP_PORT=587
SMTP_USER=admin@example.com
SMTP_PASSWORD=coloca_tu_password_o_app_password
ADMIN_EMAIL=seguridad@example.com
```

No coloques contrasenas dentro del codigo fuente. El correo del administrador se cambia con `ADMIN_EMAIL`.

## Archivos de configuracion

### Lista blanca

Archivo: `config/whitelist.csv`

Columnas:

```csv
ip,mac,description
192.168.1.10,66:77:88:99:aa:bb,Equipo autorizado de laboratorio
```

Incluye las IP y MAC autorizadas de la red de laboratorio. Puedes obtener datos locales con:

```bash
ip addr
ip link
```

### Lista de IPs peligrosas

Archivo: `config/blacklist_ips.csv`

Columnas:

```csv
ip,risk_type,description
203.0.113.10,Ejemplo educativo,IP reservada de documentacion usada como ejemplo
```

Para pruebas reales de clase, usa IPs de servidores propios o autorizados por el docente. Evita marcar servicios publicos de terceros como "peligrosos" fuera de una practica controlada.

## Ejecucion

Desde la raiz del proyecto:

```bash
source venv/bin/activate
sudo python3 src/main.py
```

Menu disponible:

```text
1. Iniciar monitoreo IDS
2. Ver lista blanca
3. Ver reporte de sitios visitados
4. Ver alertas generadas
5. Probar envio de correo
6. Salir
```

Al iniciar el monitoreo puedes escribir una interfaz especifica, por ejemplo `eth0`, `ens33` o `wlan0`, o presionar Enter para autodeteccion.

## Como probar cada modulo

### 1. Lista blanca IP/MAC

1. Edita `config/whitelist.csv` con las IP y MAC autorizadas.
2. Ejecuta el IDS y selecciona la opcion `1`.
3. Genera trafico normal desde equipos autorizados de la red.
4. Conecta o usa un equipo de laboratorio que no este en la lista blanca.
5. Revisa:

```bash
cat logs/unauthorized_devices.log
cat logs/alerts.log
```

El sistema enviara correo si `config/.env` esta configurado correctamente.

### 2. Monitoreo de sitios por DNS

1. Ejecuta el IDS con la opcion `1`.
2. En otra terminal de la VM genera una consulta DNS:

```bash
getent hosts example.com
resolvectl query example.edu
```

3. Revisa:

```bash
cat logs/site_report.log
```

Si no aparecen consultas, verifica que la interfaz sea la correcta y que el sistema no este usando DNS cifrado o un resolver no visible para Scapy.

### 3. IPs peligrosas

1. Agrega al archivo `config/blacklist_ips.csv` la IP de un servidor de laboratorio autorizado.
2. Inicia el monitoreo IDS.
3. Genera una conexion controlada hacia esa IP desde la VM o desde la red autorizada.
4. Revisa:

```bash
cat logs/threats_detected.log
cat logs/alerts.log
```

La alerta incluira IP origen, IP destino, protocolo observado, tipo de riesgo y descripcion.

### 4. Abuse/Whois

Cuando se detecta una IP incluida en `config/blacklist_ips.csv`, el sistema ejecuta el comando Linux `whois` sobre esa IP. Intenta extraer:

- Organizacion.
- Pais.
- Correo abuse.

Si no encuentra datos o falla `whois`, el correo indicara `No disponible` y el IDS continuara funcionando.

### 5. Correo

1. Configura `config/.env`.
2. Ejecuta:

```bash
sudo python3 src/main.py
```

3. Selecciona la opcion `5`.
4. Revisa la bandeja del administrador configurado en `ADMIN_EMAIL`.

## Logs

La carpeta `logs/` se crea automaticamente si no existe.

Archivos principales:

- `logs/unauthorized_devices.log`: dispositivos no autorizados por IP o MAC.
- `logs/site_report.log`: dominios DNS consultados.
- `logs/threats_detected.log`: conexiones a IPs peligrosas.
- `logs/alerts.log`: bitacora general de alertas y errores operativos.

Cada linea incluye fecha y hora.

## Limitaciones

- Es un IDS educativo por consola, no reemplaza soluciones profesionales como Suricata, Zeek o Wazuh.
- La captura requiere permisos de red.
- La visibilidad depende de la interfaz, modo de red de la VM y topologia del laboratorio.
- DNS cifrado puede impedir ver dominios consultados.
- Redes con switches pueden limitar la observacion de trafico de otros equipos.
- La consulta Whois depende del comando `whois`, conectividad y disponibilidad de servidores Whois.
- La lista negra es manual; el sistema no descarga fuentes externas de reputacion.

## Advertencia de uso autorizado

Usa este proyecto unicamente en redes propias, laboratorios universitarios o entornos donde tengas autorizacion explicita. No lo uses para interceptar contenido sensible, obtener credenciales, evadir controles, explotar sistemas ni monitorear redes de terceros.
