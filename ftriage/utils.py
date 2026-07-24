"""Utilidades transversales del triage: logging, hashing, timestamps y copia.

Aquí vive todo lo que no es ni recolección ni parseo ni informe: la cadena de
custodia (hashes), la detección de privilegios, la conversión de los distintos
epochs de Windows a ISO-8601 UTC y la copia robusta de ficheros que el sistema
mantiene bloqueados (hives del registro, bases de datos de navegador abiertas).
"""
from __future__ import annotations

import ctypes
import hashlib
import logging
import os
import platform
import shutil
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

log = logging.getLogger("ftriage")

IS_WINDOWS = platform.system() == "Windows"

# Diferencia entre el epoch de Windows (1601-01-01) y el de Unix (1970-01-01)
_EPOCH_1601 = datetime(1601, 1, 1, tzinfo=timezone.utc)
_EPOCH_1970 = datetime(1970, 1, 1, tzinfo=timezone.utc)


# --------------------------------------------------------------- logging
def setup_logging(logfile: Path | None = None, verbose: bool = False) -> None:
    """Configura logging a consola y, opcionalmente, a un fichero del caso."""
    level = logging.DEBUG if verbose else logging.INFO
    fmt = "%(asctime)s %(levelname)-7s %(message)s"
    datefmt = "%H:%M:%S"
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]
    if logfile:
        logfile.parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(logfile, encoding="utf-8"))
    logging.basicConfig(level=level, format=fmt, datefmt=datefmt, handlers=handlers)


# --------------------------------------------------------------- entorno
def is_admin() -> bool:
    """True si el proceso corre con privilegios de administrador (Windows).

    Fuera de Windows devuelve False: la recolección real solo tiene sentido
    sobre un sistema Windows vivo o una imagen montada.
    """
    if not IS_WINDOWS:
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def host_info() -> dict:
    """Metadatos del equipo, para la cabecera del informe y la cadena de custodia."""
    return {
        "hostname": platform.node(),
        "os": f"{platform.system()} {platform.release()}",
        "os_version": platform.version(),
        "architecture": platform.machine(),
        "python": platform.python_version(),
    }


# --------------------------------------------------------------- hashing
def sha256_file(path: Path, chunk: int = 1 << 20) -> str | None:
    """SHA-256 en streaming (no carga el fichero entero en memoria)."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for block in iter(lambda: f.read(chunk), b""):
                h.update(block)
        return h.hexdigest()
    except OSError as exc:
        log.warning("No se pudo hashear %s: %s", path, exc)
        return None


# ----------------------------------------------------------- timestamps
def filetime_to_iso(ft: int | None) -> str | None:
    """Windows FILETIME (intervalos de 100 ns desde 1601) -> ISO-8601 UTC."""
    if not ft:
        return None
    try:
        return (_EPOCH_1601 + timedelta(microseconds=ft / 10)).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, ValueError, OSError):
        return None


def chrome_time_to_iso(webkit: int | None) -> str | None:
    """Tiempo WebKit/Chrome (microsegundos desde 1601) -> ISO-8601 UTC."""
    if not webkit:
        return None
    try:
        return (_EPOCH_1601 + timedelta(microseconds=webkit)).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, ValueError, OSError):
        return None


def firefox_time_to_iso(prtime: int | None) -> str | None:
    """Firefox PRTime (microsegundos desde 1970) -> ISO-8601 UTC."""
    if not prtime:
        return None
    try:
        return (_EPOCH_1970 + timedelta(microseconds=prtime)).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, ValueError, OSError):
        return None


def unix_to_iso(ts: float | None) -> str | None:
    """Segundos Unix -> ISO-8601 UTC."""
    if not ts:
        return None
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, ValueError, OSError):
        return None


# --------------------------------------------------------------- copia
def _robocopy(src: Path, dst_dir: Path) -> bool:
    """Copia un único fichero en modo backup (/b), que con privilegios de
    administrador sortea el bloqueo exclusivo de los ficheros de sistema.

    robocopy usa códigos de salida como bitmask: <8 es éxito, >=8 es error.
    """
    dst_dir.mkdir(parents=True, exist_ok=True)
    try:
        res = subprocess.run(
            ["robocopy", str(src.parent), str(dst_dir), src.name,
             "/b", "/njh", "/njs", "/nc", "/ns", "/np", "/r:1", "/w:1"],
            capture_output=True, text=True, timeout=120,
        )
        return res.returncode < 8 and (dst_dir / src.name).exists()
    except (FileNotFoundError, subprocess.SubprocessError) as exc:
        log.debug("robocopy no disponible o falló para %s: %s", src, exc)
        return False


def copy_artifact(src: Path, dst_dir: Path, shadow: "ShadowCopy | None" = None) -> tuple[bool, str]:
    """Copia un artefacto aplicando una escalera de métodos y devuelve
    (éxito, método_usado) para registrarlo en la cadena de custodia.

    Orden: si hay una instantánea VSS activa se copia desde ahí (consistente y
    sin bloqueos); si no, copia directa; y si el fichero está bloqueado, se
    reintenta en modo backup con robocopy.
    """
    dst_dir.mkdir(parents=True, exist_ok=True)
    # 1) Instantánea de volumen (la vía forense "limpia", opt-in con --vss)
    if shadow is not None:
        shadow_src = shadow.translate(src)
        if shadow_src is not None:
            try:
                shutil.copy2(shadow_src, dst_dir / src.name)
                return True, "vss"
            except OSError as exc:
                log.debug("Copia VSS falló para %s: %s", src, exc)
    # 2) Copia directa (suficiente para prefetch y ficheros no bloqueados)
    try:
        shutil.copy2(src, dst_dir / src.name)
        return True, "direct"
    except (PermissionError, OSError) as exc:
        log.debug("Copia directa falló para %s (%s); intento modo backup", src, exc)
    # 3) Modo backup (robocopy /b) para ficheros bloqueados por el sistema
    if IS_WINDOWS and _robocopy(src, dst_dir):
        return True, "robocopy_backup"
    return False, "failed"


class ShadowCopy:
    """Instantánea de volumen (VSS) creada bajo demanda y borrada al salir.

    Es la forma correcta de adquirir ficheros bloqueados en un sistema vivo:
    congela un punto en el tiempo consistente y expone el volumen como un
    dispositivo del que se puede copiar sin candados. Requiere Windows y
    privilegios de administrador; si algo falla, el llamante sigue con la
    escalera de copia normal.
    """

    def __init__(self, drive: str = "C:\\"):
        self.drive = drive
        self.device: str | None = None
        self._shadow_id: str | None = None

    def __enter__(self) -> "ShadowCopy | None":
        if not (IS_WINDOWS and is_admin()):
            log.warning("VSS omitido: requiere Windows con privilegios de administrador")
            return None
        ps = (
            f"$r=(Get-WmiObject -List Win32_ShadowCopy).Create('{self.drive}','ClientAccessible');"
            "$s=Get-WmiObject Win32_ShadowCopy | Where-Object {$_.ID -eq $r.ShadowID};"
            "Write-Output ($r.ShadowID + '|' + $s.DeviceObject)"
        )
        try:
            res = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                                 capture_output=True, text=True, timeout=120)
            out = (res.stdout or "").strip()
            if "|" in out:
                self._shadow_id, self.device = out.split("|", 1)
                log.info("Instantánea VSS creada: %s", self.device)
                return self
            log.warning("No se pudo crear la instantánea VSS: %s", res.stderr.strip())
        except (FileNotFoundError, subprocess.SubprocessError) as exc:
            log.warning("VSS no disponible: %s", exc)
        return None

    def translate(self, path: Path) -> Path | None:
        """Traduce una ruta del volumen real a su equivalente en la instantánea."""
        if not self.device:
            return None
        p = str(path)
        if len(p) >= 2 and p[1] == ":":
            rel = p[2:].lstrip("\\/")
            return Path(f"{self.device}\\{rel}")
        return None

    def __exit__(self, *exc) -> None:
        if self._shadow_id:
            try:
                subprocess.run(
                    ["powershell", "-NoProfile", "-Command",
                     f"(Get-WmiObject Win32_ShadowCopy | Where-Object {{$_.ID -eq '{self._shadow_id}'}}).Delete()"],
                    capture_output=True, text=True, timeout=60,
                )
                log.info("Instantánea VSS eliminada")
            except (FileNotFoundError, subprocess.SubprocessError):
                log.debug("No se pudo eliminar la instantánea VSS %s", self._shadow_id)


def human_size(n: int) -> str:
    """Tamaño legible para el informe."""
    step = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if step < 1024 or unit == "TB":
            return f"{step:.0f} {unit}" if unit == "B" else f"{step:.1f} {unit}"
        step /= 1024
    return f"{n} B"


# ===================== helpers compartidos multiplataforma =====================
import plistlib
import struct as _struct

_EPOCH_2001 = datetime(2001, 1, 1, tzinfo=timezone.utc)


def cfabsolute_to_iso(secs: float | None) -> str | None:
    """CFAbsoluteTime de Apple (segundos desde 2001-01-01) -> ISO-8601 UTC."""
    if secs in (None, "", 0):
        return None
    try:
        return (_EPOCH_2001 + timedelta(seconds=float(secs))).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, ValueError, OSError):
        return None


def read_plist(path: Path) -> dict | None:
    """Lee un plist (binario o XML). None si no se puede."""
    try:
        with open(path, "rb") as f:
            return plistlib.load(f)
    except Exception:
        return None


# ---- historial de navegadores (compartido por los tres SO) ----
def _sqlite_ro(db: Path):
    import sqlite3
    return sqlite3.connect(f"file:{db}?mode=ro&immutable=1", uri=True)


def parse_chromium_history(db: Path) -> list[dict]:
    """Historial y descargas de Chrome/Edge/Chromium (tiempos WebKit)."""
    import sqlite3
    out: list[dict] = []
    try:
        con = _sqlite_ro(db)
    except sqlite3.Error:
        return out
    try:
        cur = con.cursor()
        cur.execute("SELECT url,title,visit_count,last_visit_time FROM urls "
                    "ORDER BY last_visit_time DESC LIMIT 5000")
        for url, title, visits, last in cur.fetchall():
            out.append({"timestamp": chrome_time_to_iso(last), "kind": "visita",
                        "summary": url or "", "detail": title or "",
                        "severity": "info", "visit_count": visits or 0, "source": db.name})
        try:
            cur.execute("SELECT target_path,tab_url,total_bytes,start_time FROM downloads "
                        "ORDER BY start_time DESC LIMIT 1000")
            for target, from_url, size, start in cur.fetchall():
                out.append({"timestamp": chrome_time_to_iso(start), "kind": "descarga",
                            "summary": from_url or "", "detail": target or "",
                            "severity": "warn", "bytes": size or 0, "source": db.name})
        except sqlite3.Error:
            pass
    finally:
        con.close()
    return out


def parse_firefox_history(db: Path) -> list[dict]:
    import sqlite3
    out: list[dict] = []
    try:
        con = _sqlite_ro(db)
    except sqlite3.Error:
        return out
    try:
        cur = con.cursor()
        cur.execute("SELECT url,title,visit_count,last_visit_date FROM moz_places "
                    "WHERE last_visit_date IS NOT NULL ORDER BY last_visit_date DESC LIMIT 5000")
        for url, title, visits, last in cur.fetchall():
            out.append({"timestamp": firefox_time_to_iso(last), "kind": "visita",
                        "summary": url or "", "detail": title or "",
                        "severity": "info", "visit_count": visits or 0, "source": db.name})
    finally:
        con.close()
    return out


def parse_safari_history(db: Path) -> list[dict]:
    """Historial de Safari (History.db, tiempos CFAbsoluteTime)."""
    import sqlite3
    out: list[dict] = []
    try:
        con = _sqlite_ro(db)
    except sqlite3.Error:
        return out
    try:
        cur = con.cursor()
        cur.execute("SELECT i.url, v.title, i.visit_count, v.visit_time "
                    "FROM history_visits v JOIN history_items i ON i.id=v.history_item "
                    "ORDER BY v.visit_time DESC LIMIT 5000")
        for url, title, visits, vtime in cur.fetchall():
            out.append({"timestamp": cfabsolute_to_iso(vtime), "kind": "visita",
                        "summary": url or "", "detail": title or "",
                        "severity": "info", "visit_count": visits or 0, "source": db.name})
    except sqlite3.Error:
        pass
    finally:
        con.close()
    return out


def parse_quarantine(db: Path) -> list[dict]:
    """LSQuarantineEventsV2 de macOS: qué se descargó y desde dónde."""
    import sqlite3
    out: list[dict] = []
    try:
        con = _sqlite_ro(db)
    except sqlite3.Error:
        return out
    try:
        cur = con.cursor()
        cur.execute("SELECT LSQuarantineTimeStamp, LSQuarantineAgentName, "
                    "LSQuarantineDataURLString, LSQuarantineOriginURLString "
                    "FROM LSQuarantineEvent ORDER BY LSQuarantineTimeStamp DESC LIMIT 2000")
        for ts, agent, data_url, origin in cur.fetchall():
            out.append({"timestamp": cfabsolute_to_iso(ts), "kind": "cuarentena",
                        "summary": data_url or origin or "", "detail": f"vía {agent or '?'}",
                        "severity": "warn", "source": db.name})
    except sqlite3.Error:
        pass
    finally:
        con.close()
    return out


# ---- utmp/wtmp/btmp de Linux (registros de inicio de sesión binarios) ----
_UTMP_FMT = "<hxxi32s4s32s256shhiii16s20s"
_UTMP_SIZE = _struct.calcsize(_UTMP_FMT)
_UTMP_TYPE = {2: "arranque", 5: "init", 6: "login", 7: "inicio de sesión",
              8: "cierre de sesión", 1: "runlevel"}


def parse_utmp(path: Path, failed: bool = False) -> list[dict]:
    """Parsea wtmp/btmp/utmp (formato utmp de glibc, %d bytes por registro)."""
    out: list[dict] = []
    try:
        raw = path.read_bytes()
    except OSError:
        return out
    for off in range(0, len(raw) - _UTMP_SIZE + 1, _UTMP_SIZE):
        (utype, _pid, line, _id, user, host, _et, _ex,
         _sess, sec, _usec, _addr, _unused) = _struct.unpack_from(_UTMP_FMT, raw, off)
        u = user.split(b"\x00", 1)[0].decode("utf-8", "replace")
        h = host.split(b"\x00", 1)[0].decode("utf-8", "replace")
        ln = line.split(b"\x00", 1)[0].decode("utf-8", "replace")
        if not u and not sec:
            continue
        kind = "acceso fallido" if failed else _UTMP_TYPE.get(utype, f"tipo {utype}")
        out.append({"timestamp": unix_to_iso(sec), "kind": kind,
                    "summary": f"{u}@{h}" if h else u,
                    "detail": f"tty {ln}" if ln else "",
                    "severity": "warn" if failed else "info", "user": u, "host": h})
    return out


def hash_file(path: Path, algos=("md5", "sha256"), chunk: int = 1 << 20) -> dict:
    """Calcula varios hashes en una sola pasada (cadena de custodia)."""
    hs = {a: hashlib.new(a) for a in algos}
    try:
        with open(path, "rb") as f:
            for block in iter(lambda: f.read(chunk), b""):
                for h in hs.values():
                    h.update(block)
        return {a: h.hexdigest() for a, h in hs.items()}
    except OSError as exc:
        log.warning("No se pudo hashear %s: %s", path, exc)
        return {a: None for a in algos}


def copy_and_record(category: str, src: Path, dest_dir: Path, manifest: list,
                    rename: str | None = None, shadow=None) -> dict:
    """Copia un artefacto, lo hashea (MD5+SHA256) y añade su entrada al manifiesto."""
    entry = {"category": category, "source": str(src),
             "collected_utc": now_utc(), "status": "ok"}
    try:
        ok, method = copy_artifact(src, dest_dir, shadow)
        dest = dest_dir / src.name
        if ok and rename:
            target = dest_dir / rename
            dest.replace(target)
            dest = target
        if ok:
            entry["artifact"] = str(dest.relative_to(dest_dir.parent.parent))
            entry["method"] = method
            entry["size"] = dest.stat().st_size
            d = hash_file(dest, ("md5", "sha256"))
            entry["md5"], entry["sha256"] = d["md5"], d["sha256"]
        else:
            entry["status"] = "failed"
            entry["error"] = "no se pudo copiar (¿permisos? ejecuta como root)"
    except Exception as exc:
        entry["status"] = "error"
        entry["error"] = f"{type(exc).__name__}: {exc}"
    manifest.append(entry)
    return entry


def file_mtime_iso(path: Path) -> str | None:
    """mtime de un fichero como ISO-8601 UTC."""
    try:
        return unix_to_iso(os.path.getmtime(path))
    except OSError:
        return None


def is_root() -> bool:
    """True si el proceso corre como root en un sistema tipo Unix."""
    if IS_WINDOWS:
        return False
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False
