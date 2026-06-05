from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass


NOT_AVAILABLE = "No disponible"


@dataclass(frozen=True)
class WhoisInfo:
    organization: str = NOT_AVAILABLE
    country: str = NOT_AVAILABLE
    abuse_email: str = NOT_AVAILABLE

    def to_email_section(self) -> str:
        return (
            "Informacion Whois/Abuse:\n"
            f"- Organizacion: {self.organization}\n"
            f"- Pais: {self.country}\n"
            f"- Correo abuse: {self.abuse_email}"
        )


def _find_first(patterns: list[str], text: str) -> str:
    for pattern in patterns:
        match = re.search(pattern, text, flags=re.IGNORECASE | re.MULTILINE)
        if match:
            value = match.group(1).strip()
            if value:
                return value
    return NOT_AVAILABLE


def _find_abuse_email(text: str) -> str:
    labeled_email = _find_first(
        [
            r"abuse-mailbox:\s*([^\s]+@[^\s]+)",
            r"OrgAbuseEmail:\s*([^\s]+@[^\s]+)",
            r"abuse-c:\s*([^\s]+@[^\s]+)",
        ],
        text,
    )
    if labeled_email != NOT_AVAILABLE:
        return labeled_email

    emails = re.findall(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", text)
    for email in emails:
        if "abuse" in email.lower():
            return email
    return NOT_AVAILABLE


def parse_whois_output(output: str) -> WhoisInfo:
    organization = _find_first(
        [
            r"OrgName:\s*(.+)",
            r"org-name:\s*(.+)",
            r"Organization:\s*(.+)",
            r"owner:\s*(.+)",
            r"netname:\s*(.+)",
        ],
        output,
    )
    country = _find_first([r"Country:\s*([A-Z]{2})", r"country:\s*([A-Z]{2})"], output)
    abuse_email = _find_abuse_email(output)
    return WhoisInfo(organization=organization, country=country, abuse_email=abuse_email)


def lookup_ip(ip_address: str, timeout_seconds: int = 8) -> WhoisInfo:
    if shutil.which("whois") is None:
        return WhoisInfo()

    try:
        result = subprocess.run(
            ["whois", ip_address],
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except Exception:
        return WhoisInfo()

    if not result.stdout.strip():
        return WhoisInfo()

    return parse_whois_output(result.stdout)
