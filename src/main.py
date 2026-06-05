from __future__ import annotations

from pathlib import Path

from config_loader import LOGS_DIR, WHITELIST_FILE, append_log, ensure_runtime_directories
from email_alerts import send_test_email
from packet_sniffer import PacketSniffer
from whitelist_monitor import WhitelistMonitor


def print_header() -> None:
    print("\nIDS Institucional")
    print("Sistema defensivo de monitoreo por consola")
    print("-" * 48)


def wait_for_enter() -> None:
    input("\nPresiona Enter para continuar...")


def show_file(path: Path, empty_message: str) -> None:
    if not path.exists():
        print(f"No existe el archivo: {path}")
        return

    content = path.read_text(encoding="utf-8").strip()
    print(content if content else empty_message)


def start_monitoring() -> None:
    interface = input("Interfaz de red (Enter para autodetectar): ").strip() or None
    sniffer = PacketSniffer()
    sniffer.start(interface=interface)


def show_whitelist() -> None:
    try:
        monitor = WhitelistMonitor()
        print(monitor.formatted_devices())
    except Exception as exc:
        print(f"No se pudo cargar la lista blanca: {exc}")


def show_site_report() -> None:
    show_file(LOGS_DIR / "site_report.log", "Aun no hay consultas DNS registradas.")


def show_alerts() -> None:
    show_file(LOGS_DIR / "alerts.log", "Aun no hay alertas registradas.")


def test_email() -> None:
    print("Enviando correo de prueba...")
    if send_test_email():
        print("Correo de prueba enviado correctamente.")
    else:
        print("No se pudo enviar el correo de prueba. Revisa config/.env y logs/alerts.log.")


def menu() -> None:
    ensure_runtime_directories()
    append_log("alerts.log", "Aplicacion IDS Institucional iniciada.")

    options = {
        "1": ("Iniciar monitoreo IDS", start_monitoring),
        "2": ("Ver lista blanca", show_whitelist),
        "3": ("Ver reporte de sitios visitados", show_site_report),
        "4": ("Ver alertas generadas", show_alerts),
        "5": ("Probar envio de correo", test_email),
        "6": ("Salir", None),
    }

    while True:
        print_header()
        for key, (label, _) in options.items():
            print(f"{key}. {label}")

        choice = input("\nSelecciona una opcion: ").strip()
        if choice == "6":
            print("Saliendo de IDS Institucional.")
            break

        selected = options.get(choice)
        if selected is None:
            print("Opcion invalida. Intenta de nuevo.")
            wait_for_enter()
            continue

        _, action = selected
        if action:
            action()
        wait_for_enter()


if __name__ == "__main__":
    if not WHITELIST_FILE.exists():
        print("Advertencia: no se encontro config/whitelist.csv.")
    menu()
