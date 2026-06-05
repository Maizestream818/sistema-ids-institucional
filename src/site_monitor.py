from __future__ import annotations

from config_loader import append_log


class SiteMonitor:
    def __init__(self) -> None:
        self.last_seen: set[tuple[str, str]] = set()

    def record_dns_query(self, src_ip: str, domain: str) -> None:
        src_ip = (src_ip or "No disponible").strip()
        domain = domain.strip().rstrip(".")
        if not domain:
            return

        event_key = (src_ip, domain)
        if event_key in self.last_seen:
            return

        self.last_seen.add(event_key)
        append_log("site_report.log", f"Consulta DNS. IP_origen={src_ip} Dominio={domain}")
        print(f"DNS registrado: {src_ip} -> {domain}")
