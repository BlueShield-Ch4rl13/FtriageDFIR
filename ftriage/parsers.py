"""Interpretación de los artefactos recolectados.

Cada parser transforma un artefacto crudo en una lista de registros normalizados
(diccionarios con un timestamp ISO-8601 UTC y campos legibles) que luego alimentan
el informe y la super-timeline. Estrategia híbrida:

  event logs   python-evtx      (Python puro, multiplataforma)
  amcache      python-registry  (Python puro, multiplataforma)
  shimcache    python-registry + parser propio del AppCompatCache
  navegadores  sqlite3          (stdlib)
  prefetch     PECmd (Eric Zimmerman) si está en el PATH o en --ez-tools;
               el formato comprimido de Win10 necesita descompresión nativa
               de Windows, así que aquí no se reimplementa.

Regla de oro: si un artefacto está corrupto, bloqueado o ausente, el parser
registra el error y devuelve lo que haya podido extraer. Nunca lanza hacia
arriba: un artefacto ilegible no puede tumbar el análisis completo.
"""
from __future__ import annotations

import csv
import logging
import os
import shutil
import sqlite3
import struct
import subprocess
import tempfile
from pathlib import Path

from . import utils

log = logging.getLogger("ftriage")


# ============================================================ Eric Zimmerman
EZ_TOOLS = {"prefetch": "PECmd.exe"}


def find_ez_tools(hint: Path | None) -> dict[str, str]:
    """Localiza las EZ Tools soportadas en --ez-tools o en el PATH."""
    found: dict[str, str] = {}
    for key, exe in EZ_TOOLS.items():
        path = None
        if hint:
            cand = Path(hint) / exe
            if cand.is_file():
                path = str(cand)
        if not path:
            path = shutil.which(exe)
        if path:
            found[key] = path
            log.info("EZ Tool detectada: %s", path)
    return found


# ================================================================= prefetch
def parse_prefetch(pf_dir: Path, pecmd: str | None) -> tuple[list[dict], str | None]:
    """Evidencia de ejecución desde los .pf, usando PECmd si está disponible."""
    if not pf_dir.is_dir() or not any(pf_dir.glob("*.pf")):
        return [], None
    if not pecmd:
        return [], "prefetch sin parsear: PECmd no encontrado (usa --ez-tools o PATH)"

    records: list[dict] = []
    with tempfile.TemporaryDirectory() as tmp:
        try:
            subprocess.run([pecmd, "-d", str(pf_dir), "--csv", tmp, "--csvf", "pf.csv"],
                           capture_output=True, text=True, timeout=300)
        except (FileNotFoundError, subprocess.SubprocessError) as exc:
            return [], f"PECmd falló: {exc}"
        csv_path = Path(tmp) / "pf.csv"
        if not csv_path.is_file():
            return [], "PECmd no generó salida CSV"
        with open(csv_path, encoding="utf-8-sig", newline="") as f:
            for row in csv.DictReader(f):
                last = _pecmd_time(row.get("LastRun"))
                previous = [_pecmd_time(row.get(f"PreviousRun{i}")) for i in range(7)]
                records.append({
                    "timestamp": last,
                    "executable": row.get("ExecutableName") or "",
                    "run_count": _to_int(row.get("RunCount")),
                    "last_run": last,
                    "previous_runs": [p for p in previous if p],
                    "source_pf": row.get("SourceFilename") or "",
                })
    records.sort(key=lambda r: r["timestamp"] or "", reverse=True)
    return records, None


def _pecmd_time(value: str | None) -> str | None:
    """'YYYY-MM-DD HH:MM:SS' de PECmd -> ISO-8601 UTC (se asume UTC)."""
    if not value or not value.strip():
        return None
    v = value.strip().replace(" ", "T")
    return v if v.endswith("Z") else v + "Z"


# ============================================================ amcache (hive)
def parse_amcache(hive: Path) -> tuple[list[dict], str | None]:
    """Programas presentes/ejecutados según Amcache.hve (incluye SHA-1)."""
    if not hive.is_file():
        return [], None
    try:
        from Registry import Registry
    except ImportError:
        return [], "amcache sin parsear: falta python-registry"

    records: list[dict] = []
    try:
        reg = Registry.Registry(str(hive))
    except Exception as exc:
        return [], f"Amcache.hve ilegible: {exc}"

    # Formato moderno (Win10 1607+): InventoryApplicationFile
    try:
        key = reg.open("Root\\InventoryApplicationFile")
        for sub in key.subkeys():
            vals = {v.name(): _safe_value(v) for v in sub.values()}
            file_id = vals.get("FileId") or ""
            records.append({
                "timestamp": utils.now_utc() if False else _key_ts(sub),
                "path": vals.get("LowerCaseLongPath") or "",
                "sha1": file_id[-40:].lower() if len(file_id) >= 40 else "",
                "publisher": vals.get("Publisher") or "",
                "product": vals.get("ProductName") or "",
                "link_date": vals.get("LinkDate") or "",
                "source": "InventoryApplicationFile",
            })
    except Registry.RegistryKeyNotFoundException:
        pass
    except Exception as exc:
        log.debug("Amcache InventoryApplicationFile: %s", exc)

    # Formato antiguo (Win7/8): Root\File\<volumen>\<id>
    if not records:
        try:
            root_file = reg.open("Root\\File")
            for vol in root_file.subkeys():
                for sub in vol.subkeys():
                    vals = {v.name(): _safe_value(v) for v in sub.values()}
                    sha1 = str(vals.get("101") or "")
                    records.append({
                        "timestamp": _key_ts(sub),
                        "path": vals.get("15") or "",
                        "sha1": sha1[-40:].lower() if len(sha1) >= 40 else "",
                        "publisher": vals.get("6") or "",
                        "product": vals.get("0") or "",
                        "link_date": "",
                        "source": "File",
                    })
        except Exception as exc:
            log.debug("Amcache Root\\File: %s", exc)

    records.sort(key=lambda r: r["timestamp"] or "", reverse=True)
    return records, None


def _key_ts(key) -> str | None:
    try:
        return key.timestamp().strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return None


def _safe_value(v):
    try:
        return v.value()
    except Exception:
        return None


# ========================================================== shimcache (hive)
def parse_shimcache(system_hive: Path) -> tuple[list[dict], str | None]:
    """AppCompatCache del hive SYSTEM: rutas y orden de inserción (Win10/7)."""
    if not system_hive.is_file():
        return [], None
    try:
        from Registry import Registry
    except ImportError:
        return [], "shimcache sin parsear: falta python-registry"

    try:
        reg = Registry.Registry(str(system_hive))
        n = reg.open("Select").value("Current").value()
        cache = (reg.open(f"ControlSet{n:03d}\\Control\\Session Manager\\AppCompatCache")
                 .value("AppCompatCache").value())
    except Exception as exc:
        return [], f"AppCompatCache no encontrado: {exc}"

    entries = _parse_appcompat(cache)
    if entries is None:
        return [], "formato de AppCompatCache no reconocido"
    for i, e in enumerate(entries):
        e["order"] = i  # 0 = entrada más reciente en la caché
    return entries, None


def _parse_appcompat(data: bytes) -> list[dict] | None:
    """Parser del AppCompatCache. Soporta la cabecera de Windows 10.

    Cada entrada Win10: firma '10ts', luego un bloque con longitud de ruta
    (UTF-16LE) y el FILETIME de última modificación del fichero.
    """
    if len(data) < 4:
        return None
    sig = struct.unpack_from("<I", data, 0)[0]

    # Windows 10/11: el primer DWORD es el offset a la primera entrada (0x30/0x34)
    if sig in (0x30, 0x34):
        return _parse_win10(data, sig)
    # Windows 7: firma 0xBADC0FEE
    if sig == 0xBADC0FEE:
        return _parse_win7(data)
    return None


def _parse_win10(data: bytes, offset: int) -> list[dict]:
    out: list[dict] = []
    pos = offset
    size = len(data)
    while pos + 12 <= size:
        if data[pos:pos + 4] != b"10ts":
            break
        # pos+4: unknown(4) ; pos+8: tamaño del resto de la entrada (4)
        ce_size = struct.unpack_from("<I", data, pos + 8)[0]
        entry_start = pos + 12
        if entry_start + 2 > size:
            break
        path_len = struct.unpack_from("<H", data, entry_start)[0]
        p = entry_start + 2
        path = data[p:p + path_len].decode("utf-16-le", errors="replace")
        p += path_len
        last_mod = None
        if p + 8 <= size:
            ft = struct.unpack_from("<Q", data, p)[0]
            last_mod = utils.filetime_to_iso(ft)
        out.append({"timestamp": last_mod, "path": path, "last_modified": last_mod})
        pos = entry_start + ce_size  # saltar al siguiente registro
    return out


def _parse_win7(data: bytes) -> list[dict]:
    out: list[dict] = []
    count = struct.unpack_from("<I", data, 4)[0]
    is64 = True  # entradas de 32 bytes en x64; asunción razonable en 2020+
    pos = 128
    entry_size = 32 if is64 else 24
    for _ in range(count):
        if pos + entry_size > len(data):
            break
        path_len = struct.unpack_from("<H", data, pos)[0]
        path_off = struct.unpack_from("<Q", data, pos + 8)[0] if is64 else struct.unpack_from("<I", data, pos + 4)[0]
        ft = struct.unpack_from("<Q", data, pos + 12)[0] if is64 else struct.unpack_from("<Q", data, pos + 8)[0]
        path = ""
        if 0 < path_len and path_off + path_len <= len(data):
            path = data[path_off:path_off + path_len].decode("utf-16-le", errors="replace")
        lm = utils.filetime_to_iso(ft)
        out.append({"timestamp": lm, "path": path, "last_modified": lm})
        pos += entry_size
    return out


# ============================================================== event logs
# ID de mayor valor en IR -> (descripción, campos de EventData a extraer)
EVENT_MAP = {
    "1102": ("Registro de auditoría de seguridad borrado", []),
    "104": ("Registro de eventos borrado", []),
    "4624": ("Inicio de sesión correcto", ["TargetUserName", "LogonType", "IpAddress", "WorkstationName"]),
    "4625": ("Inicio de sesión fallido", ["TargetUserName", "LogonType", "IpAddress", "WorkstationName"]),
    "4634": ("Cierre de sesión", ["TargetUserName"]),
    "4648": ("Inicio de sesión con credenciales explícitas", ["TargetUserName", "IpAddress"]),
    "4672": ("Privilegios especiales asignados", ["SubjectUserName"]),
    "4688": ("Creación de proceso", ["NewProcessName", "CommandLine", "ParentProcessName", "SubjectUserName"]),
    "4720": ("Cuenta de usuario creada", ["TargetUserName", "SubjectUserName"]),
    "4722": ("Cuenta de usuario habilitada", ["TargetUserName"]),
    "4724": ("Intento de restablecer contraseña", ["TargetUserName"]),
    "4728": ("Usuario añadido a grupo global de seguridad", ["TargetUserName", "MemberName"]),
    "4732": ("Usuario añadido a grupo local de seguridad", ["TargetUserName", "MemberName"]),
    "4756": ("Usuario añadido a grupo universal de seguridad", ["TargetUserName", "MemberName"]),
    "7045": ("Servicio instalado en el sistema", ["ServiceName", "ImagePath", "ServiceType", "StartType"]),
    "7034": ("Servicio terminó inesperadamente", ["param1"]),
    "1": ("Sysmon: creación de proceso", ["Image", "CommandLine", "ParentImage", "User"]),
    "3": ("Sysmon: conexión de red", ["Image", "DestinationIp", "DestinationPort", "DestinationHostname"]),
    "11": ("Sysmon: creación de fichero", ["Image", "TargetFilename"]),
    "13": ("Sysmon: valor de registro modificado", ["Image", "TargetObject"]),
    "22": ("Sysmon: consulta DNS", ["Image", "QueryName"]),
    "4104": ("PowerShell: bloque de script ejecutado", ["ScriptBlockText"]),
    "106": ("Tarea programada registrada", ["TaskName"]),
    "140": ("Tarea programada actualizada", ["TaskName"]),
    "141": ("Tarea programada eliminada", ["TaskName"]),
    "200": ("Tarea programada ejecutada (acción)", ["ActionName", "TaskName"]),
    "1116": ("Windows Defender: malware detectado", ["Threat Name", "Path"]),
    "1117": ("Windows Defender: acción sobre malware", ["Threat Name", "Action Name"]),
    "21": ("RDP: inicio de sesión (LocalSessionManager)", ["User", "Address"]),
    "25": ("RDP: reconexión de sesión", ["User", "Address"]),
}

_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


def parse_eventlogs(evtx_dir: Path, max_per_file: int = 50000) -> tuple[list[dict], str | None]:
    """Extrae los eventos de alto valor de todos los .evtx recolectados."""
    if not evtx_dir.is_dir():
        return [], None
    try:
        from Evtx.Evtx import Evtx
        from lxml import etree  # noqa: F401 (lo usa _parse_event_xml)
    except ImportError:
        return [], "event logs sin parsear: falta python-evtx"

    wanted = set(EVENT_MAP)
    records: list[dict] = []
    errors: list[str] = []
    for evtx_file in sorted(evtx_dir.glob("*.evtx")):
        seen = 0
        try:
            with Evtx(str(evtx_file)) as elog:
                for rec in elog.records():
                    seen += 1
                    if seen > max_per_file:
                        break
                    try:
                        parsed = _parse_event_xml(rec.xml(), wanted)
                        if parsed:
                            parsed["log_file"] = evtx_file.name
                            records.append(parsed)
                    except Exception:
                        continue
        except Exception as exc:
            errors.append(f"{evtx_file.name}: {exc}")
            log.debug("Error leyendo %s: %s", evtx_file.name, exc)

    records.sort(key=lambda r: r["timestamp"] or "", reverse=True)
    return records, ("; ".join(errors) if errors else None)


def _parse_event_xml(xml_str: str, wanted: set[str]) -> dict | None:
    """Normaliza un registro de evento (XML) si su ID es de interés."""
    from lxml import etree

    root = etree.fromstring(xml_str.encode("utf-8"))
    system = root.find(f"{_NS}System")
    if system is None:
        return None
    eid_el = system.find(f"{_NS}EventID")
    eid = (eid_el.text or "").strip() if eid_el is not None else ""
    if eid not in wanted:
        return None

    time_el = system.find(f"{_NS}TimeCreated")
    ts = time_el.get("SystemTime") if time_el is not None else None
    ts = _norm_evtx_time(ts)
    channel_el = system.find(f"{_NS}Channel")
    computer_el = system.find(f"{_NS}Computer")

    # EventData: pares Name -> texto
    edata: dict[str, str] = {}
    edata_el = root.find(f"{_NS}EventData")
    if edata_el is not None:
        for i, data in enumerate(edata_el.findall(f"{_NS}Data")):
            name = data.get("Name") or f"Data{i}"
            edata[name] = (data.text or "").strip()

    desc, fields = EVENT_MAP[eid]
    details = {f: edata[f] for f in fields if edata.get(f)}
    return {
        "timestamp": ts,
        "event_id": eid,
        "description": desc,
        "channel": channel_el.text if channel_el is not None else "",
        "computer": computer_el.text if computer_el is not None else "",
        "details": details,
    }


def _norm_evtx_time(ts: str | None) -> str | None:
    """'2024-01-01T12:00:00.000000Z' -> '2024-01-01T12:00:00Z'."""
    if not ts:
        return None
    ts = ts.replace(" ", "T")
    if "." in ts:
        ts = ts.split(".", 1)[0] + "Z"
    elif not ts.endswith("Z"):
        ts += "Z"
    return ts


# =============================================================== navegadores
def parse_browsers(browser_dir: Path) -> tuple[list[dict], str | None]:
    """Historial y descargas de Chrome/Edge (WebKit) y Firefox (PRTime)."""
    if not browser_dir.is_dir():
        return [], None
    records: list[dict] = []
    errors: list[str] = []
    for db in sorted(browser_dir.iterdir()):
        if not db.is_file():
            continue
        name = db.name.lower()
        try:
            if "places.sqlite" in name:
                records += _firefox(db)
            elif "history" in name:  # Chrome / Edge
                records += _chromium(db)
        except sqlite3.Error as exc:
            errors.append(f"{db.name}: {exc}")
            log.debug("SQLite error en %s: %s", db.name, exc)

    records.sort(key=lambda r: r["timestamp"] or "", reverse=True)
    return records, ("; ".join(errors) if errors else None)


def _open_ro(db: Path) -> sqlite3.Connection:
    """Abre la BD en modo solo-lectura e inmutable (no altera el original)."""
    return sqlite3.connect(f"file:{db}?mode=ro&immutable=1", uri=True)


def _label(db: Path) -> str:
    stem = db.stem
    if stem.lower().endswith("_history"):  # nombre "usuario_Perfil_History"
        return stem
    return db.parent.name or "browser"


def _chromium(db: Path) -> list[dict]:
    con = _open_ro(db)
    try:
        out = []
        cur = con.cursor()
        cur.execute("SELECT url, title, visit_count, last_visit_time "
                    "FROM urls ORDER BY last_visit_time DESC LIMIT 5000")
        for url, title, visits, last in cur.fetchall():
            out.append({
                "timestamp": utils.chrome_time_to_iso(last),
                "kind": "visita",
                "url": url or "",
                "title": title or "",
                "visit_count": visits or 0,
                "source": db.name,
            })
        # Descargas (muy relevantes: qué se bajó y a dónde)
        try:
            cur.execute("SELECT target_path, tab_url, total_bytes, start_time "
                        "FROM downloads ORDER BY start_time DESC LIMIT 1000")
            for target, from_url, size, start in cur.fetchall():
                out.append({
                    "timestamp": utils.chrome_time_to_iso(start),
                    "kind": "descarga",
                    "url": from_url or "",
                    "title": target or "",
                    "bytes": size or 0,
                    "source": db.name,
                })
        except sqlite3.Error:
            pass
        return out
    finally:
        con.close()


def _firefox(db: Path) -> list[dict]:
    con = _open_ro(db)
    try:
        out = []
        cur = con.cursor()
        cur.execute("SELECT url, title, visit_count, last_visit_date "
                    "FROM moz_places WHERE last_visit_date IS NOT NULL "
                    "ORDER BY last_visit_date DESC LIMIT 5000")
        for url, title, visits, last in cur.fetchall():
            out.append({
                "timestamp": utils.firefox_time_to_iso(last),
                "kind": "visita",
                "url": url or "",
                "title": title or "",
                "visit_count": visits or 0,
                "source": db.name,
            })
        return out
    finally:
        con.close()


# =================================================================== fachada
def _to_int(v) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def parse_all(out_dir: Path, ez_hint: Path | None) -> dict:
    """Ejecuta todos los parsers sobre los artefactos ya recolectados."""
    art = out_dir / "artifacts"
    ez = find_ez_tools(ez_hint)
    result: dict[str, list[dict]] = {}
    errors: list[dict] = []

    def run(name: str, fn, *args):
        records, err = fn(*args)
        result[name] = records
        if err:
            errors.append({"parser": name, "error": err})
        log.info("[%s] %d registro(s)%s", name, len(records),
                 f" · aviso: {err}" if err else "")

    run("eventlogs", parse_eventlogs, art / "eventlogs")
    run("prefetch", parse_prefetch, art / "prefetch", ez.get("prefetch"))
    run("amcache", parse_amcache, art / "amcache" / "Amcache.hve")
    run("shimcache", parse_shimcache, art / "registry" / "SYSTEM")
    run("browsers", parse_browsers, art / "browsers")

    result["_errors"] = errors
    return result
