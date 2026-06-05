from __future__ import annotations

import csv
import os
from datetime import datetime
from pathlib import Path
from typing import Iterable

try:
    from dotenv import load_dotenv
except ImportError:
    def load_dotenv(*_args: object, **_kwargs: object) -> bool:
        return False


PROJECT_ROOT = Path(__file__).resolve().parents[1]
CONFIG_DIR = PROJECT_ROOT / "config"
LOGS_DIR = PROJECT_ROOT / "logs"

WHITELIST_FILE = CONFIG_DIR / "whitelist.csv"
BLACKLIST_FILE = CONFIG_DIR / "blacklist_ips.csv"
ENV_FILE = CONFIG_DIR / ".env"


def ensure_runtime_directories() -> None:
    """Create runtime directories required by the IDS."""
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)


def load_environment() -> None:
    """Load environment variables from config/.env when present."""
    if ENV_FILE.exists():
        load_dotenv(ENV_FILE)
    else:
        load_dotenv()


def get_env_value(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


def timestamp() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def append_log(log_name: str, message: str) -> None:
    ensure_runtime_directories()
    log_path = LOGS_DIR / log_name
    with log_path.open("a", encoding="utf-8") as log_file:
        log_file.write(f"[{timestamp()}] {message}\n")


def read_csv_rows(path: Path, required_columns: Iterable[str]) -> list[dict[str, str]]:
    if not path.exists():
        raise FileNotFoundError(f"No existe el archivo requerido: {path}")

    with path.open("r", newline="", encoding="utf-8") as csv_file:
        reader = csv.DictReader(csv_file)
        if reader.fieldnames is None:
            raise ValueError(f"El archivo CSV no tiene encabezados: {path}")

        missing_columns = set(required_columns) - set(reader.fieldnames)
        if missing_columns:
            missing = ", ".join(sorted(missing_columns))
            raise ValueError(f"El archivo {path} no contiene las columnas: {missing}")

        return [
            {key: (value or "").strip() for key, value in row.items()}
            for row in reader
            if any((value or "").strip() for value in row.values())
        ]
