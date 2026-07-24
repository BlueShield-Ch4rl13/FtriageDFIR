"""Selección de la plataforma de triage.

Detecta el sistema anfitrión o respeta el objetivo indicado con --target-os, de
modo que se pueda triar tanto el equipo vivo como una imagen montada de otro
sistema operativo (p. ej., analizar una imagen Windows desde una estación
Linux con --target-os windows --root /mnt/imagen).
"""
from __future__ import annotations

import sys

from . import utils

_ALIASES = {
    "windows": "windows", "win": "windows",
    "linux": "linux", "unix": "linux", "gnu/linux": "linux",
    "macos": "macos", "mac": "macos", "osx": "macos", "darwin": "macos", "apple": "macos",
}


def detect_host() -> str:
    if utils.IS_WINDOWS:
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    return "linux"


def normalize(target: str | None) -> str:
    if not target or target.lower() == "auto":
        return detect_host()
    key = target.strip().lower()
    if key not in _ALIASES:
        raise ValueError(f"SO objetivo no reconocido: {target} "
                         f"(usa: windows, linux, macos, o auto)")
    return _ALIASES[key]


def select(target: str | None):
    """Devuelve el módulo de plataforma con la interfaz collect()/parse()."""
    name = normalize(target)
    if name == "linux":
        from . import linux
        return linux
    if name == "macos":
        from . import macos
        return macos
    from . import windows_adapter
    return windows_adapter
