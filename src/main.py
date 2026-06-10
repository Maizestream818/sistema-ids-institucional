from __future__ import annotations

import atexit
from pathlib import Path

from colors import (
    BG, BOLD, CYAN, FG, R, WHITE,
    blank_line, clear_screen, dim, error, fill_line,
    info, menu_option, reset_terminal, separator, set_background, success, warning,
)
from config_loader import (
    LOGS_DIR, WHITELIST_FILE, append_log, ensure_runtime_directories,
    get_env_value, load_environment
)
from email_alerts import send_email
from packet_sniffer import PacketSniffer
from virustotal import interactive_lookup as vt_interactive_lookup
from whitelist_monitor import (
    WhitelistMonitor,
    add_device_interactive,
    remove_device_interactive,
)


BANNER_LINES = [
    "",
    f"  {BOLD}{CYAN}  ██╗██████╗ ███████╗{R}",
    f"  {BOLD}{CYAN}  ██║██╔══██╗██╔════╝{R}",
    f"  {BOLD}{CYAN}  ██║██║  ██║███████╗{R}",
    f"  {BOLD}{CYAN}  ██║██║  ██║╚════██║{R}",
    f"  {BOLD}{CYAN}  ██║██████╔╝███████║{R}",
    f"  {BOLD}{CYAN}  ╚═╝╚═════╝ ╚══════╝{R}",
    f"  {dim('  Sistema defensivo de monitoreo')}",
    "",
]


def print_header() -> None:
    clear_screen()
    set_background()
    for line in BANNER_LINES:
        print(fill_line(line))
    print(fill_line(separator("─", 48)))


def print_sub_header(title: str) -> None:
    """Print a sub-section header without clearing the screen."""
    print(fill_line(""))
    print(fill_line(info(f"  ── {title} ──")))
    print(fill_line(""))


def wait_for_enter() -> None:
    input(f"{BG}{FG}\n{dim('  Presiona Enter para continuar...')}")


def show_file(path: Path, empty_message: str) -> None:
    if not path.exists():
        print(fill_line(warning(f"  No existe el archivo: {path}")))
        return

    content = path.read_text(encoding="utf-8").strip()
    if not content:
        print(fill_line(dim(f"  {empty_message}")))
        return

    for line in content.splitlines():
        print(fill_line(f"{BG}{FG}  {line}"))


def start_monitoring() -> None:
    interface = input(f"{BG}{FG}  {info('Interfaz de red')} {dim('(Enter para autodetectar)')}: ").strip() or None
    sniffer = PacketSniffer()
    sniffer.start(interface=interface)


# ── Whitelist submenu ──

def manage_whitelist() -> None:
    """Submenu for whitelist management: view, add, remove."""
    sub_options = {
        "1": ("Ver dispositivos autorizados", "📋", _show_whitelist),
        "2": ("Agregar dispositivo", "➕", add_device_interactive),
        "3": ("Quitar dispositivo", "➖", remove_device_interactive),
        "4": ("Volver al menu principal", "↩ ", None),
    }

    while True:
        print(fill_line(""))
        print(fill_line(info("  ── Gestion de lista blanca ──")))
        print(fill_line(""))
        for key, (lbl, icon, _) in sub_options.items():
            print(fill_line(menu_option(key, f"{icon}  {lbl}")))
        print(fill_line(""))

        choice = input(f"{BG}  {BOLD}{WHITE}▶ Opcion:{R} ").strip()
        if choice == "4":
            break

        selected = sub_options.get(choice)
        if selected is None:
            print(fill_line(warning("  Opcion invalida.")))
            continue

        _, _, action = selected
        if action:
            print(fill_line(""))
            action()


def _show_whitelist() -> None:
    try:
        monitor = WhitelistMonitor()
        output = monitor.formatted_devices()
        for line in output.splitlines():
            print(fill_line(line))
    except Exception as exc:
        print(fill_line(error(f"  No se pudo cargar la lista blanca: {exc}")))


# ── Reports ──

def show_site_report() -> None:
    show_file(LOGS_DIR / "site_report.log", "Aun no hay consultas DNS registradas.")


def show_alerts() -> None:
    show_file(LOGS_DIR / "alerts.log", "Aun no hay alertas registradas.")


# ── Email report ──

def _build_report() -> str:
    """Build a text summary of the current IDS state for emailing."""
    sections: list[str] = ["=== Reporte IDS Institucional ===\n"]

    # Whitelist summary
    try:
        monitor = WhitelistMonitor()
        sections.append(f"Dispositivos autorizados: {len(monitor.devices)}")
        for d in monitor.devices:
            sections.append(f"  - {d.ip}  {d.mac}  ({d.description})")
    except Exception:
        sections.append("Dispositivos autorizados: no se pudo cargar")
    sections.append("")

    # Alerts summary
    alerts_path = LOGS_DIR / "alerts.log"
    if alerts_path.exists():
        lines = alerts_path.read_text(encoding="utf-8").strip().splitlines()
        sections.append(f"Total de alertas registradas: {len(lines)}")
        # Last 10 alerts
        recent = lines[-10:]
        if recent:
            sections.append("\nUltimas alertas:")
            for line in recent:
                sections.append(f"  {line}")
    else:
        sections.append("Alertas: sin registro aun")
    sections.append("")

    # Threats
    threats_path = LOGS_DIR / "threats_detected.log"
    if threats_path.exists():
        lines = threats_path.read_text(encoding="utf-8").strip().splitlines()
        sections.append(f"Amenazas detectadas: {len(lines)}")
        for line in lines[-5:]:
            sections.append(f"  {line}")
    else:
        sections.append("Amenazas detectadas: 0")
    sections.append("")

    # Unauthorized devices
    unauth_path = LOGS_DIR / "unauthorized_devices.log"
    if unauth_path.exists():
        lines = unauth_path.read_text(encoding="utf-8").strip().splitlines()
        sections.append(f"Dispositivos no autorizados detectados: {len(lines)}")
        for line in lines[-5:]:
            sections.append(f"  {line}")
    else:
        sections.append("Dispositivos no autorizados: 0")
    sections.append("")

    # DNS
    dns_path = LOGS_DIR / "site_report.log"
    if dns_path.exists():
        lines = dns_path.read_text(encoding="utf-8").strip().splitlines()
        sections.append(f"Consultas DNS registradas: {len(lines)}")
    else:
        sections.append("Consultas DNS: 0")

    sections.append("\n--- Fin del reporte ---")
    return "\n".join(sections)


def send_report_email() -> None:
    """Send a full IDS status report by email."""
    print(fill_line(info("  Generando reporte...")))
    report = _build_report()

    print(fill_line(""))
    # Show preview
    for line in report.splitlines():
        print(fill_line(f"{BG}{FG}  {line}"))

    print(fill_line(""))
    confirm = input(f"{BG}{FG}  {info('¿Enviar este reporte por correo?')} {dim('(s/n)')}: ").strip().lower()
    if confirm not in ("s", "si", "y", "yes"):
        print(fill_line(dim("  Envio cancelado.")))
        return

    load_environment()
    default_email = get_env_value("ADMIN_EMAIL")
    
    if default_email:
        email_prompt = f"  {info('Correo destino')} {dim(f'(Enter para usar {default_email})')}: "
    else:
        email_prompt = f"  {info('Correo destino')}: "
        
    to_email = input(f"{BG}{FG}{email_prompt}").strip()
    final_email = to_email if to_email else default_email

    if not final_email:
        print(fill_line(error("  ✘ No se proporcionó un correo destino y no hay ADMIN_EMAIL en config/.env")))
        return

    print(fill_line(info(f"  Enviando reporte a {final_email}...")))
    if send_email("Reporte IDS Institucional", report, to_email=final_email):
        print(fill_line(success("  ✔ Reporte enviado correctamente.")))
        append_log("alerts.log", f"Reporte IDS enviado por correo a {final_email}.")
    else:
        print(fill_line(error("  ✘ No se pudo enviar el reporte. Revisa config/.env")))


# ── Main menu ──

def menu() -> None:
    ensure_runtime_directories()
    append_log("alerts.log", "Aplicacion IDS Institucional iniciada.")

    # Restore terminal on exit (Ctrl+C, etc.)
    atexit.register(reset_terminal)

    options = {
        "1": ("Iniciar monitoreo IDS", "🛡", start_monitoring),
        "2": ("Gestionar lista blanca", "📋", manage_whitelist),
        "3": ("Ver reporte de sitios visitados", "🌐", show_site_report),
        "4": ("Ver alertas generadas", "🔔", show_alerts),
        "5": ("Enviar reporte por correo", "✉ ", send_report_email),
        "6": ("Consultar IP en VirusTotal", "🔍", vt_interactive_lookup),
        "7": ("Salir", "🚪", None),
    }

    while True:
        print_header()
        print(blank_line())
        for key, (lbl, icon, _) in options.items():
            print(fill_line(menu_option(key, f"{icon}  {lbl}")))
        print(blank_line())

        choice = input(f"{BG}  {BOLD}{WHITE}▶ Selecciona una opcion:{R} ").strip()
        if choice == "7":
            clear_screen()
            reset_terminal()
            print(info("\n  Saliendo de IDS Institucional. ¡Hasta pronto!\n"))
            break

        selected = options.get(choice)
        if selected is None:
            print(fill_line(warning("  Opcion invalida. Intenta de nuevo.")))
            wait_for_enter()
            continue

        _, _, action = selected
        if action:
            print(blank_line())
            action()
        wait_for_enter()


if __name__ == "__main__":
    if not WHITELIST_FILE.exists():
        print(warning("⚠  Advertencia: no se encontro config/whitelist.csv."))
    menu()
