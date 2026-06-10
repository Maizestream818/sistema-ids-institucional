from __future__ import annotations

import csv
import ipaddress
import re
from dataclasses import dataclass

from colors import BG, BOLD, CYAN, FG, GREEN, R, RED, WHITE, YELLOW, dim, error, fill_line, info, success, warning
from config_loader import WHITELIST_FILE, append_log, read_csv_rows
from email_alerts import send_email


MAC_PATTERN = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")


@dataclass(frozen=True)
class AuthorizedDevice:
    ip: str
    mac: str
    description: str


def normalize_mac(mac_address: str) -> str:
    return mac_address.strip().lower().replace("-", ":")


def is_valid_ip(ip_address: str) -> bool:
    try:
        ipaddress.ip_address(ip_address)
        return True
    except ValueError:
        return False


def is_valid_mac(mac_address: str) -> bool:
    return bool(MAC_PATTERN.match(normalize_mac(mac_address)))


def load_whitelist() -> list[AuthorizedDevice]:
    rows = read_csv_rows(WHITELIST_FILE, ["ip", "mac", "description"])
    devices: list[AuthorizedDevice] = []

    for row in rows:
        ip_address = row["ip"]
        mac_address = normalize_mac(row["mac"])
        if not is_valid_ip(ip_address):
            append_log("alerts.log", f"IP invalida en whitelist.csv: {ip_address}")
            continue
        if not is_valid_mac(mac_address):
            append_log("alerts.log", f"MAC invalida en whitelist.csv: {mac_address}")
            continue
        devices.append(
            AuthorizedDevice(
                ip=ip_address,
                mac=mac_address,
                description=row.get("description", "Sin descripcion"),
            )
        )

    return devices


def _save_whitelist(devices: list[AuthorizedDevice]) -> None:
    """Write the full device list back to the CSV file."""
    with WHITELIST_FILE.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["ip", "mac", "description"])
        for device in devices:
            writer.writerow([device.ip, device.mac, device.description])


def add_device_interactive() -> None:
    """Prompt the user for IP, MAC, and description, then add to whitelist."""
    print(fill_line(info("  ── Agregar dispositivo a la lista blanca ──")))
    print(fill_line(""))

    ip_addr = input(f"{BG}{FG}  IP del dispositivo: ").strip()
    if not ip_addr:
        print(fill_line(warning("  ⚠  No se ingreso ninguna IP.")))
        return
    if not is_valid_ip(ip_addr):
        print(fill_line(error(f"  ✘ '{ip_addr}' no es una IP valida.")))
        return

    mac_addr = input(f"{BG}{FG}  MAC del dispositivo {dim('(ej: aa:bb:cc:dd:ee:ff)')}: ").strip()
    if not mac_addr:
        print(fill_line(warning("  ⚠  No se ingreso ninguna MAC.")))
        return
    mac_addr = normalize_mac(mac_addr)
    if not is_valid_mac(mac_addr):
        print(fill_line(error(f"  ✘ '{mac_addr}' no es una MAC valida.")))
        return

    description = input(f"{BG}{FG}  Descripcion {dim('(ej: Laptop de Juan)')}: ").strip()
    if not description:
        description = "Sin descripcion"

    devices = load_whitelist()

    # Check for duplicates
    for d in devices:
        if d.ip == ip_addr and d.mac == mac_addr:
            print(fill_line(warning(f"  ⚠  El dispositivo {ip_addr} / {mac_addr} ya esta en la lista.")))
            return

    new_device = AuthorizedDevice(ip=ip_addr, mac=mac_addr, description=description)
    devices.append(new_device)
    _save_whitelist(devices)
    append_log("alerts.log", f"Dispositivo agregado a whitelist: IP={ip_addr} MAC={mac_addr} Desc={description}")
    print(fill_line(success(f"  ✔ Dispositivo agregado: {ip_addr}  {mac_addr}  {description}")))


def remove_device_interactive() -> None:
    """Show numbered list of devices and let the user pick one to remove."""
    devices = load_whitelist()

    if not devices:
        print(fill_line(warning("  ⚠  La lista blanca esta vacia.")))
        return

    print(fill_line(info("  ── Quitar dispositivo de la lista blanca ──")))
    print(fill_line(""))
    print(fill_line(f"  {BOLD}{CYAN}{'#':<5} {'IP':<18} {'MAC':<20} {'Descripcion'}{R}"))
    print(fill_line(f"  {dim('─' * 65)}"))

    for i, device in enumerate(devices, 1):
        print(fill_line(
            f"  {YELLOW}{i:<5}{R}"
            f"{WHITE}{device.ip:<18}{R} "
            f"{dim(device.mac):<29}  "
            f"{GREEN}{device.description}{R}"
        ))

    print(fill_line(""))
    choice = input(f"{BG}{FG}  Numero del dispositivo a quitar {dim('(0 para cancelar)')}: ").strip()

    try:
        index = int(choice)
    except ValueError:
        print(fill_line(error("  ✘ Entrada invalida.")))
        return

    if index == 0:
        print(fill_line(dim("  Cancelado.")))
        return

    if index < 1 or index > len(devices):
        print(fill_line(error(f"  ✘ No existe el dispositivo #{index}.")))
        return

    removed = devices.pop(index - 1)
    _save_whitelist(devices)
    append_log("alerts.log", f"Dispositivo eliminado de whitelist: IP={removed.ip} MAC={removed.mac}")
    print(fill_line(success(f"  ✔ Eliminado: {removed.ip}  {removed.mac}  {removed.description}")))


class WhitelistMonitor:
    def __init__(self) -> None:
        self.devices = load_whitelist()
        self.authorized_ips = {device.ip for device in self.devices}
        self.authorized_macs = {device.mac for device in self.devices}
        self.authorized_pairs = {(device.ip, device.mac) for device in self.devices}
        self.reported_events: set[tuple[str, str]] = set()

    def reload(self) -> None:
        self.__init__()

    def check_device(self, src_ip: str, src_mac: str, context: str = "") -> bool:
        src_ip = (src_ip or "").strip()
        src_mac = normalize_mac(src_mac or "")
        reasons = []

        ip_is_valid = bool(src_ip and is_valid_ip(src_ip))
        mac_is_valid = bool(src_mac and is_valid_mac(src_mac))

        if ip_is_valid and src_ip not in self.authorized_ips:
            reasons.append("IP no autorizada")
        if mac_is_valid and src_mac not in self.authorized_macs:
            reasons.append("MAC no autorizada")
        if (
            ip_is_valid
            and mac_is_valid
            and src_ip in self.authorized_ips
            and src_mac in self.authorized_macs
            and (src_ip, src_mac) not in self.authorized_pairs
        ):
            reasons.append("Par IP/MAC no autorizado")

        if not reasons:
            return False

        event_key = (src_ip, src_mac)
        if event_key in self.reported_events:
            return True

        self.reported_events.add(event_key)
        reason_text = ", ".join(reasons)
        context_text = f" Contexto: {context}." if context else ""
        log_message = f"Dispositivo no autorizado detectado. IP={src_ip or 'No disponible'} MAC={src_mac or 'No disponible'} Motivo={reason_text}.{context_text}"

        append_log("unauthorized_devices.log", log_message)
        append_log("alerts.log", log_message)

        email_body = (
            "IDS Institucional detecto un dispositivo no autorizado.\n\n"
            f"IP origen: {src_ip or 'No disponible'}\n"
            f"MAC origen: {src_mac or 'No disponible'}\n"
            f"Motivo: {reason_text}\n"
            f"Contexto: {context or 'No disponible'}\n\n"
            "Revise si el equipo pertenece a la red de laboratorio autorizada."
        )
        send_email("Alerta IDS: dispositivo no autorizado", email_body)
        print(warning(f"  ⚠  Dispositivo no autorizado: IP={src_ip}  MAC={src_mac}  [{reason_text}]"))
        return True

    def formatted_devices(self) -> str:
        if not self.devices:
            return warning("  No hay dispositivos validos cargados en la lista blanca.")

        header_line = f"  {BOLD}{CYAN}{'IP':<18} {'MAC':<20} {'Descripcion'}{R}"
        sep = f"  {dim('─' * 60)}"
        lines = [header_line, sep]
        for device in self.devices:
            lines.append(
                f"  {WHITE}{device.ip:<18}{R} "
                f"{dim(device.mac)}  "
                f"{GREEN}{device.description}{R}"
            )
        return "\n".join(lines)
