from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

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
        print(log_message)
        return True

    def formatted_devices(self) -> str:
        if not self.devices:
            return "No hay dispositivos validos cargados en la lista blanca."

        lines = ["IP | MAC | Descripcion", "-" * 60]
        for device in self.devices:
            lines.append(f"{device.ip} | {device.mac} | {device.description}")
        return "\n".join(lines)
