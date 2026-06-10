from __future__ import annotations

import ipaddress
from typing import Any

from colors import dim, error, info, success, warning
from config_loader import append_log, ensure_runtime_directories
from site_monitor import SiteMonitor
from threat_intel import ThreatIntel
from whitelist_monitor import WhitelistMonitor


def _is_local_candidate(ip_address: str) -> bool:
    try:
        parsed = ipaddress.ip_address(ip_address)
    except ValueError:
        return False
    return parsed.is_private or parsed.is_link_local or parsed.is_loopback


class PacketSniffer:
    def __init__(self) -> None:
        ensure_runtime_directories()
        self.whitelist_monitor = WhitelistMonitor()
        self.site_monitor = SiteMonitor()
        self.threat_intel = ThreatIntel()

    def start(self, interface: str | None = None, packet_count: int = 0) -> None:
        try:
            from scapy.all import sniff
        except ImportError:
            print("Scapy no esta instalado. Ejecuta: pip install -r requirements.txt")
            append_log("alerts.log", "No se pudo iniciar monitoreo: Scapy no esta instalado.")
            return

        print(success("  ✔ Monitoreo IDS iniciado. Presiona Ctrl+C para detener."))
        print(dim("    Solo se registran metadatos necesarios para alertas y bitacoras."))

        try:
            sniff(
                prn=self.process_packet,
                store=False,
                filter="arp or ip",
                iface=interface or None,
                count=packet_count,
            )
        except PermissionError:
            print(error("  ✘ Permiso insuficiente. Ejecuta con sudo o configura setcap."))
            append_log("alerts.log", "Permiso insuficiente para capturar paquetes.")
        except KeyboardInterrupt:
            print(info("\n  Monitoreo detenido por el usuario."))
        except Exception as exc:
            print(error(f"  ✘ No se pudo iniciar o mantener la captura: {exc}"))
            append_log("alerts.log", f"Error de captura: {exc}")

    def process_packet(self, packet: Any) -> None:
        try:
            self._process_arp(packet)
            self._process_ip(packet)
        except Exception as exc:
            append_log("alerts.log", f"Error procesando paquete: {exc}")

    def _process_arp(self, packet: Any) -> None:
        from scapy.layers.l2 import ARP

        if not packet.haslayer(ARP):
            return

        arp_layer = packet[ARP]
        src_ip = getattr(arp_layer, "psrc", "")
        src_mac = getattr(arp_layer, "hwsrc", "")
        self.whitelist_monitor.check_device(src_ip, src_mac, "ARP")

    def _process_ip(self, packet: Any) -> None:
        from scapy.layers.dns import DNS, DNSQR
        from scapy.layers.inet import IP, TCP, UDP
        from scapy.layers.l2 import Ether

        if not packet.haslayer(IP):
            return

        ip_layer = packet[IP]
        src_ip = getattr(ip_layer, "src", "")
        dst_ip = getattr(ip_layer, "dst", "")
        src_mac = packet[Ether].src if packet.haslayer(Ether) else ""

        if _is_local_candidate(src_ip) or self._is_unknown_mac(src_mac):
            self.whitelist_monitor.check_device(src_ip, src_mac, "Trafico IP local")

        if packet.haslayer(DNS) and packet.haslayer(DNSQR) and packet[DNS].qr == 0:
            domain = packet[DNSQR].qname
            if isinstance(domain, bytes):
                domain = domain.decode("utf-8", errors="ignore")
            self.site_monitor.record_dns_query(src_ip, str(domain))

        protocol = "IP"
        if packet.haslayer(TCP):
            protocol = "TCP"
        elif packet.haslayer(UDP):
            protocol = "UDP"
        self.threat_intel.check_connection(src_ip, dst_ip, protocol)

    def _is_unknown_mac(self, mac_address: str) -> bool:
        if not mac_address:
            return False
        normalized = mac_address.strip().lower().replace("-", ":")
        return normalized not in self.whitelist_monitor.authorized_macs
