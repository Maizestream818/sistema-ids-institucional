"""ANSI color utilities for terminal output.

Uses 24-bit RGB colors exclusively so output looks identical
regardless of the user's terminal color scheme.
"""
from __future__ import annotations

import os
import re
import shutil

# ── Background & default foreground (dark navy + light gray) ──
BG = "\033[48;2;15;17;26m"
FG = "\033[38;2;200;205;215m"

# Full reset (clears everything — only for exiting the app)
FULL_RESET = "\033[0m"

# Soft reset: clears bold/dim but keeps BG + FG
R = "\033[22;23;24;25;27;28;29m" + BG + FG

# ── Styles ──
BOLD = "\033[1m"
DIM = "\033[2m"

# ── Foreground RGB colors (bright, high contrast on dark bg) ──
RED = "\033[38;2;255;85;85m"
GREEN = "\033[38;2;80;250;123m"
YELLOW = "\033[38;2;255;220;80m"
BLUE = "\033[38;2;100;150;255m"
MAGENTA = "\033[38;2;200;130;255m"
CYAN = "\033[38;2;80;220;255m"
WHITE = "\033[38;2;240;242;245m"
GRAY = "\033[38;2;130;140;155m"


# ── Screen control ──

def get_terminal_width() -> int:
    return shutil.get_terminal_size((80, 24)).columns


def clear_screen() -> None:
    os.system("clear" if os.name != "nt" else "cls")


def set_background() -> None:
    """Set background + foreground for all subsequent output."""
    print(f"{BG}{FG}", end="", flush=True)


def fill_line(text: str = "") -> str:
    """Pad line to full terminal width with background color."""
    visible = re.sub(r"\033\[[^m]*m", "", text)
    padding = max(0, get_terminal_width() - len(visible))
    return f"{BG}{text}{' ' * padding}"


def blank_line() -> str:
    return fill_line()


def reset_terminal() -> None:
    """Restore terminal to default state."""
    print(FULL_RESET, end="", flush=True)


# ── Text formatting helpers ──
# Each function wraps text in color and then returns to BG+FG
# so the background is never interrupted.

def success(text: str) -> str:
    return f"{GREEN}{text}{R}"


def error(text: str) -> str:
    return f"{RED}{text}{R}"


def warning(text: str) -> str:
    return f"{YELLOW}{text}{R}"


def info(text: str) -> str:
    return f"{CYAN}{text}{R}"


def danger(text: str) -> str:
    return f"{BOLD}{RED}{text}{R}"


def header(text: str) -> str:
    return f"{BOLD}{CYAN}{text}{R}"


def dim(text: str) -> str:
    return f"{GRAY}{text}{R}"


def label(text: str) -> str:
    return f"{BOLD}{WHITE}{text}{R}"


def menu_option(key: str, text: str) -> str:
    return f"{BG}  {BOLD}{CYAN}{key}{R}{GRAY}.{R} {WHITE}{text}{R}"


def separator(char: str = "─", length: int = 50) -> str:
    return f"{BG}{GRAY}{char * length}{R}"
