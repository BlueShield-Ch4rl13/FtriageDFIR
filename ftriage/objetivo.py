"""Identidad del equipo INVESTIGADO (no del analista).

Antes el informe ponía el nombre y el sistema operativo de la máquina que
ejecutaba ftriage (platform.node()). Al analizar una imagen montada, el
informe decía que el equipo era la estación del analista: el ejemplo
"Windows 11" llevaba una cadena de kernel Linux.

Aquí se lee de la propia evidencia:
  Windows  colmenas SYSTEM (nombre) y SOFTWARE (versión), de la copia del caso
           si existe, si no de la raíz
  Linux    etc/hostname y etc/os-release
  macOS    preferences.plist (nombre) y SystemVersion.plist (versión)

En triage en vivo (la raíz es el propio sistema) se completa con lo que dice
el sistema en ejecución.
"""
from __future__ import annotations

import logging
import platform
import plistlib
from pathlib import Path

from . import utils

log = logging.getLogger("ftriage")


def es_en_vivo(root: Path, target_os: str, host_os: str) -> bool:
    """La raíz es el sistema que está corriendo (no una imagen montada)."""
    return target_os == host_os and str(root).rstrip("\\/") in ("", "C:")


def _windows(root: Path, out_dir: Path) -> dict:
    info: dict = {}
    try:
        from Registry import Registry  # python-registry
    except ImportError:
        return info

    def colmena(nombre: str) -> Path | None:
        for cand in (out_dir / "artifacts" / "registry" / nombre,
                     root / "Windows" / "System32" / "config" / nombre):
            if cand.is_file():
                return cand
        return None

    sistema = colmena("SYSTEM")
    if sistema:
        try:
            reg = Registry.Registry(str(sistema))
            actual = reg.open("Select").value("Current").value()
            clave = reg.open(f"ControlSet{actual:03d}\\Control\\ComputerName\\ComputerName")
            info["hostname"] = clave.value("ComputerName").value()
        except Exception as exc:  # colmena sucia o incompleta: se dice y se sigue
            log.debug("Sin nombre de equipo en SYSTEM: %s", exc)
    software = colmena("SOFTWARE")
    if software:
        try:
            cv = Registry.Registry(str(software)).open("Microsoft\\Windows NT\\CurrentVersion")
            valores = {v.name(): v.value() for v in cv.values()}
            info["os"] = valores.get("ProductName", "Windows")
            build = valores.get("CurrentBuild") or valores.get("CurrentBuildNumber")
            if build:
                info["os_version"] = f"{valores.get('DisplayVersion', '')} build {build}".strip()
                # Windows 11 sigue diciendo "Windows 10" en ProductName
                if info["os"].startswith("Windows 10") and str(build).isdigit() and int(build) >= 22000:
                    info["os"] = info["os"].replace("Windows 10", "Windows 11", 1)
        except Exception as exc:
            log.debug("Sin versión en SOFTWARE: %s", exc)
    return info


def _linux(root: Path) -> dict:
    info: dict = {}
    try:
        info["hostname"] = (root / "etc" / "hostname").read_text(encoding="utf-8").strip().split()[0]
    except (OSError, IndexError):
        pass
    try:
        campos = {}
        for linea in (root / "etc" / "os-release").read_text(encoding="utf-8").splitlines():
            if "=" in linea:
                k, v = linea.split("=", 1)
                campos[k] = v.strip().strip('"')
        info["os"] = campos.get("PRETTY_NAME") or campos.get("NAME", "Linux")
        if campos.get("VERSION_ID"):
            info["os_version"] = campos["VERSION_ID"]
    except OSError:
        pass
    return info


def _macos(root: Path) -> dict:
    info: dict = {}
    try:
        with open(root / "System" / "Library" / "CoreServices" / "SystemVersion.plist", "rb") as f:
            v = plistlib.load(f)
        info["os"] = f"{v.get('ProductName', 'macOS')} {v.get('ProductVersion', '')}".strip()
        info["os_version"] = v.get("ProductBuildVersion", "")
    except (OSError, plistlib.InvalidFileException):
        pass
    try:
        with open(root / "Library" / "Preferences" / "SystemConfiguration" / "preferences.plist", "rb") as f:
            pref = plistlib.load(f)
        sistema = (pref.get("System") or {}).get("System") or {}
        info["hostname"] = sistema.get("ComputerName") or sistema.get("HostName") or ""
    except (OSError, plistlib.InvalidFileException):
        pass
    return info


def describir(root: Path, target_os: str, out_dir: Path, en_vivo: bool) -> dict:
    """Nombre, SO y arquitectura del equipo investigado, y de dónde salen."""
    root = Path(root)
    lector = {"windows": lambda: _windows(root, out_dir), "linux": lambda: _linux(root),
              "macos": lambda: _macos(root)}.get(target_os, dict)
    info = {k: v for k, v in lector().items() if v}
    info["origen"] = "evidencia (raíz %s)" % root
    if en_vivo:
        info.setdefault("hostname", platform.node())
        info.setdefault("os", f"{platform.system()} {platform.release()}")
        info.setdefault("os_version", platform.version())
        info["architecture"] = platform.machine()
        info["origen"] = "sistema en vivo"
    info.setdefault("hostname", "desconocido")
    info.setdefault("os", target_os)
    info["acquisition"] = "en vivo" if en_vivo else "imagen o disco montado"
    return info


def estacion() -> dict:
    """La máquina del analista: va aparte en el informe, nunca como el objetivo."""
    return utils.host_info()
