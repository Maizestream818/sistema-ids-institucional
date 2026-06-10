from __future__ import annotations

from dataclasses import dataclass

from colors import (
    BG, BOLD, CYAN, FG, GREEN, R, RED, WHITE, YELLOW,
    dim, error, info, success, warning,
)
from config_loader import append_log, get_env_value


VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3"
NOT_AVAILABLE = "No disponible"


@dataclass(frozen=True)
class VirusTotalReport:
    """Resultado resumido de una consulta a VirusTotal para una IP."""

    ip: str
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    owner: str = NOT_AVAILABLE
    country: str = NOT_AVAILABLE
    network: str = NOT_AVAILABLE
    error_msg: str = ""

    @property
    def is_threat(self) -> bool:
        return self.malicious > 0 or self.suspicious > 0

    @property
    def total_engines(self) -> int:
        return self.malicious + self.suspicious + self.harmless + self.undetected

    def _color_count(self, label: str, count: int, color: str) -> str:
        return f"  {WHITE}{label}:{R} {BOLD}{color}{count}{R}{dim(f'/{self.total_engines}')}"

    def summary(self) -> str:
        if self.error_msg:
            return error(f"  ✘ [VirusTotal] Error consultando {self.ip}: {self.error_msg}")
        return (
            f"\n  {BOLD}{CYAN}━━━ VirusTotal: {self.ip} ━━━{R}\n"
            f"{self._color_count('Maliciosos', self.malicious, RED)}\n"
            f"{self._color_count('Sospechosos', self.suspicious, YELLOW)}\n"
            f"{self._color_count('Inofensivos', self.harmless, GREEN)}\n"
            f"{self._color_count('Sin deteccion', self.undetected, WHITE)}\n"
            f"  {WHITE}Propietario:{R} {self.owner}\n"
            f"  {WHITE}Pais:{R}        {self.country}\n"
            f"  {WHITE}Red:{R}         {self.network}\n"
            f"  {BOLD}{CYAN}{'━' * 40}{R}"
        )

    def to_log_line(self) -> str:
        if self.error_msg:
            return f"VT_error={self.error_msg}"
        return (
            f"VT_malicious={self.malicious} VT_suspicious={self.suspicious} "
            f"VT_harmless={self.harmless} VT_undetected={self.undetected} "
            f"VT_owner={self.owner} VT_country={self.country} VT_network={self.network}"
        )


def _get_api_key() -> str:
    """Retrieve the VirusTotal API key from the environment."""
    return get_env_value("VIRUSTOTAL_API_KEY")


def lookup_ip(ip_address: str) -> VirusTotalReport:
    """Query VirusTotal API v3 for the reputation of *ip_address*.

    Returns a VirusTotalReport with the analysis stats. If the API key
    is not configured or the request fails, the report's *error_msg* field
    describes the issue.
    """
    api_key = _get_api_key()
    if not api_key:
        return VirusTotalReport(
            ip=ip_address,
            error_msg="API key de VirusTotal no configurada. Agrega VIRUSTOTAL_API_KEY en config/.env",
        )

    try:
        import requests
    except ImportError:
        return VirusTotalReport(
            ip=ip_address,
            error_msg="El modulo 'requests' no esta instalado. Ejecuta: pip install -r requirements.txt",
        )

    url = f"{VIRUSTOTAL_API_URL}/ip_addresses/{ip_address}"
    headers = {"x-apikey": api_key}

    try:
        response = requests.get(url, headers=headers, timeout=15)
    except requests.RequestException as exc:
        append_log("alerts.log", f"VirusTotal: error de conexion para {ip_address}: {exc}")
        return VirusTotalReport(ip=ip_address, error_msg=f"Error de conexion: {exc}")

    if response.status_code == 401:
        return VirusTotalReport(ip=ip_address, error_msg="API key invalida o sin permisos.")
    if response.status_code == 429:
        return VirusTotalReport(ip=ip_address, error_msg="Limite de solicitudes excedido (rate limit).")
    if response.status_code != 200:
        return VirusTotalReport(
            ip=ip_address,
            error_msg=f"Respuesta HTTP {response.status_code}: {response.text[:200]}",
        )

    try:
        data = response.json()
    except ValueError:
        return VirusTotalReport(ip=ip_address, error_msg="Respuesta no valida de VirusTotal.")

    attributes = data.get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})

    return VirusTotalReport(
        ip=ip_address,
        malicious=stats.get("malicious", 0),
        suspicious=stats.get("suspicious", 0),
        harmless=stats.get("harmless", 0),
        undetected=stats.get("undetected", 0),
        owner=attributes.get("as_owner", NOT_AVAILABLE),
        country=attributes.get("country", NOT_AVAILABLE),
        network=attributes.get("network", NOT_AVAILABLE),
    )


def interactive_lookup() -> None:
    """Menu-driven function to let the user query an IP on VirusTotal."""
    api_key = _get_api_key()
    if not api_key:
        print(warning(
            "\n  ⚠  VIRUSTOTAL_API_KEY no esta configurada.\n"
            "     Agrega tu API key en config/.env para usar esta funcion.\n"
            "     Puedes obtener una API key gratuita en: https://www.virustotal.com/\n"
        ))
        return

    ip_address = input(f"{BG}{FG}  {info('Ingresa la IP a consultar')}: ").strip()
    if not ip_address:
        print(warning("  No se ingreso ninguna IP."))
        return

    # Validar que sea una IP real
    try:
        import ipaddress as _ipa
        _ipa.ip_address(ip_address)
    except ValueError:
        print(error(f"  ✘ '{ip_address}' no es una direccion IP valida."))
        return

    print(info(f"\n  Consultando VirusTotal para {ip_address}..."))
    report = lookup_ip(ip_address)
    print(report.summary())

    if not report.error_msg:
        append_log(
            "virustotal.log",
            f"Consulta manual IP={ip_address} {report.to_log_line()}",
        )
