from __future__ import annotations

import smtplib
from dataclasses import dataclass
from email.message import EmailMessage

from colors import error, success, warning
from config_loader import append_log, get_env_value, load_environment


@dataclass(frozen=True)
class EmailConfig:
    smtp_server: str
    smtp_port: int
    smtp_user: str
    smtp_password: str
    admin_email: str


def load_email_config() -> EmailConfig:
    load_environment()
    port_value = get_env_value("SMTP_PORT", "587")

    try:
        smtp_port = int(port_value)
    except ValueError:
        smtp_port = 587
        append_log("alerts.log", "SMTP_PORT invalido. Se uso el puerto 587 por defecto.")

    return EmailConfig(
        smtp_server=get_env_value("SMTP_SERVER"),
        smtp_port=smtp_port,
        smtp_user=get_env_value("SMTP_USER"),
        smtp_password=get_env_value("SMTP_PASSWORD"),
        admin_email=get_env_value("ADMIN_EMAIL"),
    )


def _validate_config(config: EmailConfig, has_custom_to: bool = False) -> list[str]:
    missing = []
    if not config.smtp_server:
        missing.append("SMTP_SERVER")
    if not config.smtp_user:
        missing.append("SMTP_USER")
    if not config.smtp_password:
        missing.append("SMTP_PASSWORD")
    if not config.admin_email and not has_custom_to:
        missing.append("ADMIN_EMAIL")
    return missing


def send_email(subject: str, body: str, config: EmailConfig | None = None, to_email: str | None = None) -> bool:
    config = config or load_email_config()
    missing = _validate_config(config, bool(to_email))

    if missing:
        append_log(
            "alerts.log",
            "No se envio correo porque faltan variables: " + ", ".join(missing),
        )
        print(warning("  ⚠  Correo no enviado. Faltan variables en config/.env: " + ", ".join(missing)))
        return False

    target_email = to_email or config.admin_email

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = config.smtp_user
    message["To"] = target_email
    message.set_content(body)

    try:
        with smtplib.SMTP(config.smtp_server, config.smtp_port, timeout=15) as smtp:
            smtp.starttls()
            smtp.login(config.smtp_user, config.smtp_password)
            smtp.send_message(message)
        append_log("alerts.log", f"Correo enviado correctamente. Asunto: {subject}")
        return True
    except Exception as exc:
        append_log("alerts.log", f"Error al enviar correo: {exc}")
        print(error(f"  ✘ No se pudo enviar el correo: {exc}"))
        return False


def send_test_email() -> bool:
    subject = "Prueba de correo IDS Institucional"
    body = (
        "Este es un mensaje de prueba generado por IDS Institucional.\n"
        "Si recibes este correo, la configuracion SMTP funciona correctamente."
    )
    return send_email(subject, body)
