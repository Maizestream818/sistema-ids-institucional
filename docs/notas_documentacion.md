# Notas de documentacion

## Alcance

IDS Institucional es un proyecto escolar defensivo. Su alcance es observar metadatos de red en una red propia o autorizada, registrar eventos y emitir alertas por correo.

## Datos registrados

- Fecha y hora del evento.
- IP origen.
- MAC origen cuando el paquete la expone.
- Dominio DNS consultado.
- IP destino cuando coincide con la lista negra.
- Tipo de alerta y nivel de riesgo configurado.
- Informacion Whois/Abuse basica para IPs peligrosas.

## Datos no registrados

- Contrasenas.
- Cookies.
- Cuerpo de paginas HTTP.
- Contenido de archivos.
- Credenciales.
- Mensajes personales o contenido sensible.

## Consideraciones de laboratorio

La deteccion de dispositivos autorizados funciona mejor con trafico ARP y redes locales IPv4 privadas. En redes con NAT, paquetes entrantes desde Internet pueden aparecer con la MAC del router o gateway, por eso el sistema evita tratar automaticamente toda IP publica remota como dispositivo local.

La captura DNS depende de que las consultas sean visibles en la interfaz monitoreada. DNS cifrado, resolvers locales o configuraciones especiales pueden reducir los eventos observables.
