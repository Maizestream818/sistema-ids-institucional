from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from abuse_lookup import lookup_ip
from colors import BG, BOLD, CYAN, FG, R, RED, WHITE, danger, dim
from config_loader import BLACKLIST_FILE, append_log, read_csv_rows
from email_alerts import send_email
from virustotal import lookup_ip as vt_lookup_ip


@dataclass(frozen=True)
class DangerousIP:
    ip: str
    risk_type: str
    description: str


def is_valid_ip(ip_address: str) -> bool:
    try:
        ipaddress.ip_address(ip_address)
        return True
    except ValueError:
        return False


def load_blacklist() -> dict[str, DangerousIP]:
    rows = read_csv_rows(BLACKLIST_FILE, ["ip", "risk_type", "description"])
    blacklist: dict[str, DangerousIP] = {}

    for row in rows:
        ip_address = row["ip"]
        if not is_valid_ip(ip_address):
            append_log("alerts.log", f"IP invalida en blacklist_ips.csv: {ip_address}")
            continue
        blacklist[ip_address] = DangerousIP(
            ip=ip_address,
            risk_type=row.get("risk_type", "Riesgo no especificado"),
            description=row.get("description", "Sin descripcion"),
        )

    return blacklist


class ThreatIntel:
    def __init__(self) -> None:
        self.blacklist = load_blacklist()
        self.reported_events: set[tuple[str, str]] = set()

    def reload(self) -> None:
        self.__init__()

    def check_connection(self, src_ip: str, dst_ip: str, protocol: str = "IP") -> bool:
        src_ip = (src_ip or "No disponible").strip()
        dst_ip = (dst_ip or "").strip()
        if dst_ip not in self.blacklist:
            return False

        event_key = (src_ip, dst_ip)
        if event_key in self.reported_events:
            return True

        self.reported_events.add(event_key)
        threat = self.blacklist[dst_ip]
        whois_info = lookup_ip(dst_ip)
        vt_report = vt_lookup_ip(dst_ip)

        log_message = (
            "IP peligrosa detectada. "
            f"IP_origen={src_ip} IP_destino={dst_ip} Protocolo={protocol} "
            f"Riesgo={threat.risk_type} Descripcion={threat.description} "
            f"Organizacion={whois_info.organization} Pais={whois_info.country} "
            f"Abuse={whois_info.abuse_email} {vt_report.to_log_line()}"
        )
        append_log("threats_detected.log", log_message)
        append_log("alerts.log", log_message)

        vt_section = ""
        if not vt_report.error_msg:
            vt_section = (
                f"\n\nAnalisis VirusTotal:\n"
                f"- Maliciosos: {vt_report.malicious}/{vt_report.total_engines}\n"
                f"- Sospechosos: {vt_report.suspicious}/{vt_report.total_engines}\n"
                f"- Propietario: {vt_report.owner}\n"
                f"- Pais: {vt_report.country}\n"
                f"- Red: {vt_report.network}"
            )
        elif vt_report.error_msg:
            vt_section = f"\n\nVirusTotal: {vt_report.error_msg}"

        email_body = (
            "Alerta de Emergencia generada por IDS Institucional.\n\n"
            f"IP origen: {src_ip}\n"
            f"IP destino: {dst_ip}\n"
            f"Protocolo observado: {protocol}\n"
            f"Tipo de riesgo: {threat.risk_type}\n"
            f"Descripcion: {threat.description}\n\n"
            f"{whois_info.to_email_section()}"
            f"{vt_section}\n\n"
            "La alerta se basa en metadatos de red y la lista config/blacklist_ips.csv."
        )
        send_email("Alerta de Emergencia IDS Institucional", email_body)

        print(
            f"{BG}{FG}  {BOLD}{RED}🚨 AMENAZA{R} "
            f"{danger(dst_ip)} ← {dim(src_ip)}  "
            f"{WHITE}[{threat.risk_type}]{R}  "
            f"{dim(threat.description)}"
        )
        return True

    def formatted_blacklist(self) -> str:
        if not self.blacklist:
            return "No hay IPs peligrosas validas cargadas."

        header_line = f"  {BOLD}{CYAN}{'IP':<18} {'Riesgo':<20} {'Descripcion'}{R}"
        sep = f"  {dim('─' * 70)}"
        lines = [header_line, sep]
        for threat in self.blacklist.values():
            lines.append(
                f"  {RED}{threat.ip:<18}{R} "
                f"{WHITE}{threat.risk_type:<20}{R} "
                f"{dim(threat.description)}"
            )
        return "\n".join(lines)
