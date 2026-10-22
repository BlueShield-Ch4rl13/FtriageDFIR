"""Datos volátiles, recogidos ANTES que los ficheros (RFC 3227, orden de volatilidad).

Procesos, conexiones de red, sesiones y configuración de red desaparecen al
apagar el equipo o en minutos. Solo tienen sentido en triage en vivo: en una
imagen montada no existen.

La memoria RAM completa no la vuelca ftriage: para eso, una herramienta
dedicada (AVML en Linux, WinPmem en Windows, una solución de EDR en macOS)
antes de lanzar el triage. Cada salida se guarda en artifacts/volatiles/ y
entra en el manifiesto con su hash, como cualquier otro artefacto.
"""
from __future__ import annotations

import logging
import shutil
import subprocess
from pathlib import Path

from . import utils

log = logging.getLogger("ftriage")

# (nombre del fichero, orden). Primero lo más volátil: red y procesos.
COMANDOS = {
    "windows": [
        ("netstat_ano.txt", ["netstat", "-ano"]),
        ("tasklist_v.txt", ["tasklist", "/v"]),
        ("tasklist_svc.txt", ["tasklist", "/svc"]),
        ("arp_a.txt", ["arp", "-a"]),
        ("ipconfig_dns.txt", ["ipconfig", "/displaydns"]),
        ("ipconfig_all.txt", ["ipconfig", "/all"]),
        ("query_user.txt", ["query", "user"]),
        ("net_session.txt", ["net", "session"]),
        ("schtasks.txt", ["schtasks", "/query", "/fo", "csv", "/v"]),
    ],
    "linux": [
        ("ss_tupan.txt", ["ss", "-tupan"]),
        ("ps_auxwwf.txt", ["ps", "auxwwf"]),
        ("ip_neigh.txt", ["ip", "neigh"]),
        ("ip_addr.txt", ["ip", "addr"]),
        ("ip_route.txt", ["ip", "route"]),
        ("who.txt", ["who", "-a"]),
        ("lsmod.txt", ["lsmod"]),
        ("mount.txt", ["mount"]),
    ],
    "macos": [
        ("lsof_i.txt", ["lsof", "-nP", "-i"]),
        ("netstat_an.txt", ["netstat", "-an"]),
        ("ps_axww.txt", ["ps", "axwwo", "pid,ppid,user,lstart,command"]),
        ("arp_a.txt", ["arp", "-a"]),
        ("ifconfig.txt", ["ifconfig", "-a"]),
        ("who.txt", ["who", "-a"]),
        ("kextstat.txt", ["kextstat"]),
    ],
}


def recoger(target_os: str, out_dir: Path, manifest: list, timeout: int = 60) -> None:
    """Ejecuta los comandos del SO y añade cada salida al manifiesto."""
    destino = out_dir / "artifacts" / "volatiles"
    destino.mkdir(parents=True, exist_ok=True)
    log.info("[volatiles] recogiendo procesos, red y sesiones antes que los ficheros")
    for nombre, orden in COMANDOS.get(target_os, []):
        entry = {"category": "volatiles", "source": " ".join(orden),
                 "collected_utc": utils.now_utc(), "status": "ok", "method": "comando"}
        if not shutil.which(orden[0]):
            entry.update(status="failed", error=f"{orden[0]} no está en este sistema")
            manifest.append(entry)
            continue
        fichero = destino / nombre
        try:
            r = subprocess.run(orden, capture_output=True, timeout=timeout)
            fichero.write_bytes(r.stdout + (b"\n--- stderr ---\n" + r.stderr if r.stderr else b""))
            d = utils.hash_file(fichero, ("md5", "sha256"))
            entry.update(artifact=str(fichero.relative_to(out_dir)), size=fichero.stat().st_size,
                         md5=d["md5"], sha256=d["sha256"], exit_code=r.returncode,
                         note="salida de un comando: no hay original que comparar")
        except (OSError, subprocess.SubprocessError) as exc:
            entry.update(status="error", error=f"{type(exc).__name__}: {exc}")
        manifest.append(entry)
