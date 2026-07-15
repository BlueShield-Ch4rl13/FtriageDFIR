"""Plataforma macOS: recolección y parseo de artefactos forenses.

Artefactos cubiertos:
  persistence  LaunchDaemons/LaunchAgents (system y por usuario) — la vía de
               persistencia más común en macOS
  shell        historial de zsh/bash por usuario
  browsers     Safari (History.db), Chrome/Edge, Firefox
  quarantine   LSQuarantineEventsV2 — qué se descargó y desde dónde (Gatekeeper)
  accounts     usuarios locales de dslocal (UID 0, shells)
  logs         system.log / install.log
  unified_log  log unificado (vía `log show`) filtrado a sshd/sudo/tcc/security

Cada parser normaliza a {timestamp, kind, summary, detail, severity}. Los
parseos de SQLite/plist se ejecutan en cualquier SO; la captura del unified log
solo en un macOS vivo (necesita el binario `log`).
"""
from __future__ import annotations

import logging
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from . import utils

log = logging.getLogger("ftriage")

LABEL = "macOS"
CATEGORIES = ["persistence", "shell", "browsers", "quarantine", "accounts", "logs", "unified_log"]

# Rutas sospechosas en argumentos de un LaunchAgent/Daemon
_SUSPICIOUS_PATH = re.compile(
    r"(/tmp/|/private/tmp/|/Users/Shared/|/var/tmp/|curl\s|base64|osascript|"
    r"python\s+-c|/dev/tcp/|nc\s)", re.IGNORECASE)


# ================================================================ recolección
def _users(root: Path) -> list[Path]:
    u = root / "Users"
    skip = {"Shared", "Guest", ".localized"}
    users = [p for p in u.iterdir() if p.is_dir() and p.name not in skip] if u.is_dir() else []
    vr = root / "var" / "root"
    if vr.is_dir():
        users.append(vr)
    return users


def _enumerate(root: Path, cat: str) -> list[tuple[Path, str | None]]:
    r = root
    out: list[tuple[Path, str | None]] = []

    if cat == "persistence":
        for d in ("Library/LaunchDaemons", "Library/LaunchAgents"):
            p = r / d
            if p.is_dir():
                out += [(f, None) for f in sorted(p.glob("*.plist"))]
        for user in _users(r):
            la = user / "Library" / "LaunchAgents"
            if la.is_dir():
                out += [(f, f"{user.name}_{f.name}") for f in la.glob("*.plist")]
        out.append((r / "etc" / "crontab", None))

    elif cat == "shell":
        for user in _users(r):
            for n in (".zsh_history", ".bash_history", ".sh_history"):
                f = user / n
                if f.exists():
                    out.append((f, f"{user.name}_{n.lstrip('.')}"))

    elif cat == "browsers":
        for user in _users(r):
            saf = user / "Library" / "Safari" / "History.db"
            if saf.exists():
                out.append((saf, f"{user.name}_Safari_History.db"))
            asupp = user / "Library" / "Application Support"
            for vendor in ("Google/Chrome", "Microsoft Edge"):
                udata = asupp / vendor
                if udata.is_dir():
                    for hist in udata.glob("*/History"):
                        out.append((hist, f"{user.name}_{hist.parent.name}_History"))
            ff = asupp / "Firefox" / "Profiles"
            if ff.is_dir():
                for places in ff.glob("*/places.sqlite"):
                    out.append((places, f"{user.name}_{places.parent.name}_places.sqlite"))

    elif cat == "quarantine":
        for user in _users(r):
            q = user / "Library" / "Preferences" / "com.apple.LaunchServices.QuarantineEventsV2"
            if q.exists():
                out.append((q, f"{user.name}_QuarantineEventsV2"))

    elif cat == "accounts":
        d = r / "var" / "db" / "dslocal" / "nodes" / "Default" / "users"
        if d.is_dir():
            out += [(f, None) for f in sorted(d.glob("*.plist"))]

    elif cat == "logs":
        base = r / "var" / "log"
        for n in ("system.log", "install.log"):
            f = base / n
            if f.exists():
                out.append((f, None))
        out += [(p, None) for p in sorted(base.glob("system.log.*"))]

    return [(p, rn) for p, rn in out if p.exists()]


def _collect_unified_log(dest_dir: Path, manifest: list, days: int = 3) -> None:
    """Exporta el unified log a NDJSON con `log show` (solo macOS vivo)."""
    if not shutil.which("log"):
        log.info("[unified_log] binario `log` no disponible (¿no es macOS?)")
        return
    dest_dir.mkdir(parents=True, exist_ok=True)
    out_file = dest_dir / "unified_log.ndjson"
    cmd = ["log", "show", "--style", "ndjson", "--last", f"{days}d",
           "--predicate",
           'process == "sshd" OR process == "sudo" OR subsystem == "com.apple.TCC" '
           'OR process == "tccd" OR subsystem == "com.apple.securityd"']
    try:
        with open(out_file, "w", encoding="utf-8") as f:
            subprocess.run(cmd, stdout=f, stderr=subprocess.DEVNULL, timeout=900, check=False)
    except (subprocess.SubprocessError, OSError) as exc:
        log.warning("[unified_log] `log show` falló: %s", exc)
        return
    if out_file.exists() and out_file.stat().st_size:
        entry = {"category": "unified_log", "source": "log show", "method": "log_show",
                 "collected_utc": utils.now_utc(), "status": "ok",
                 "artifact": str(out_file.relative_to(dest_dir.parent.parent)),
                 "size": out_file.stat().st_size}
        d = utils.hash_file(out_file, ("md5", "sha256"))
        entry["md5"], entry["sha256"] = d["md5"], d["sha256"]
        manifest.append(entry)


def collect(root: Path, out_dir: Path, categories: list[str], opts=None) -> list[dict]:
    root = Path(root)
    art = out_dir / "artifacts"
    manifest: list[dict] = []
    for cat in categories:
        if cat == "unified_log":
            _collect_unified_log(art / "unified_log", manifest)
            continue
        sources = _enumerate(root, cat)
        if not sources:
            log.info("[%s] sin artefactos encontrados", cat)
            continue
        log.info("[%s] recolectando %d artefacto(s)", cat, len(sources))
        for src, rename in sources:
            utils.copy_and_record(cat, src, art / cat, manifest, rename)
    ok = sum(1 for e in manifest if e["status"] == "ok")
    log.info("Recolección macOS terminada: %d/%d artefactos", ok, len(manifest))
    return manifest


# ===================================================================== parseo
def _plist_val(d: dict, key: str):
    """dslocal guarda los valores como listas de un elemento."""
    v = d.get(key)
    if isinstance(v, list) and v:
        return v[0]
    return v


def _parse_persistence(d: Path) -> tuple[list[dict], str | None]:
    if not d.is_dir():
        return [], None
    recs: list[dict] = []
    for f in sorted(d.iterdir()):
        if not f.is_file():
            continue
        ts = utils.file_mtime_iso(f)
        if f.name == "crontab":
            try:
                for line in f.read_text(errors="replace").splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        recs.append({"timestamp": ts, "kind": "cron",
                                     "summary": line[:250], "detail": "crontab", "severity": "info"})
            except OSError:
                pass
            continue
        pl = utils.read_plist(f)
        if pl is None:
            continue
        label = pl.get("Label") or f.stem
        args = pl.get("ProgramArguments")
        prog = " ".join(args) if isinstance(args, list) else (pl.get("Program") or "")
        run_at_load = pl.get("RunAtLoad", False)
        user_agent = "LaunchAgents" in str(f) and "/Users/" in str(f)
        suspicious = bool(_SUSPICIOUS_PATH.search(prog))
        sev = "crit" if suspicious else ("warn" if user_agent else "info")
        recs.append({"timestamp": ts, "kind": "launchd",
                     "summary": label, "detail": prog[:250] or "(sin programa)",
                     "severity": sev, "run_at_load": bool(run_at_load)})
    recs.sort(key=lambda r: r["timestamp"] or "", reverse=True)
    return recs, None


_SUSPICIOUS_CMD = re.compile(
    r"(curl\s+.*\|\s*(?:bash|sh)|base64\s+-D|osascript|/dev/tcp/|nc\s+.*-e|"
    r"python.*socket|chmod\s+\+x|xattr\s+-d)", re.IGNORECASE)


def _parse_shell(d: Path) -> tuple[list[dict], str | None]:
    if not d.is_dir():
        return [], None
    recs: list[dict] = []
    for f in sorted(d.iterdir()):
        if not f.is_file():
            continue
        user = f.name.split("_", 1)[0]
        try:
            lines = f.read_text(errors="replace").splitlines()
        except OSError:
            continue
        pending = None
        for line in lines:
            if line.startswith(": ") and ";" in line:
                try:
                    pending = utils.unix_to_iso(int(line[2:].split(":", 1)[0]))
                    line = line.split(";", 1)[1]
                except (ValueError, IndexError):
                    pass
            cmd = line.strip()
            if not cmd:
                continue
            recs.append({"timestamp": pending, "kind": "comando",
                         "summary": cmd[:300], "detail": user,
                         "severity": "warn" if _SUSPICIOUS_CMD.search(cmd) else "info"})
            pending = None
    return recs, None


def _parse_browsers(d: Path) -> tuple[list[dict], str | None]:
    if not d.is_dir():
        return [], None
    recs: list[dict] = []
    for f in sorted(d.iterdir()):
        if not f.is_file():
            continue
        name = f.name.lower()
        if "places.sqlite" in name:
            recs += utils.parse_firefox_history(f)
        elif name.endswith("history.db"):
            recs += utils.parse_safari_history(f)
        elif "history" in name:
            recs += utils.parse_chromium_history(f)
    recs.sort(key=lambda r: r["timestamp"] or "", reverse=True)
    return recs, None


def _parse_quarantine(d: Path) -> tuple[list[dict], str | None]:
    if not d.is_dir():
        return [], None
    recs: list[dict] = []
    for f in sorted(d.iterdir()):
        if f.is_file() and "quarantine" in f.name.lower():
            recs += utils.parse_quarantine(f)
    recs.sort(key=lambda r: r["timestamp"] or "", reverse=True)
    return recs, None


def _parse_accounts(d: Path) -> tuple[list[dict], str | None]:
    if not d.is_dir():
        return [], None
    recs: list[dict] = []
    for f in sorted(d.glob("*.plist")):
        pl = utils.read_plist(f)
        if pl is None:
            continue
        name = _plist_val(pl, "name") or f.stem
        uid = str(_plist_val(pl, "uid") or "")
        shell = _plist_val(pl, "shell") or ""
        home = _plist_val(pl, "home") or ""
        if str(name).startswith("_"):  # cuentas de servicio del sistema
            continue
        is_root = uid == "0" and name != "root"
        has_shell = shell.rsplit("/", 1)[-1] not in ("false", "nologin", "")
        if is_root or has_shell:
            recs.append({"timestamp": utils.file_mtime_iso(f),
                         "kind": "cuenta UID 0" if uid == "0" else "cuenta local",
                         "summary": f"{name} (uid {uid})", "detail": f"{shell} · {home}",
                         "severity": "crit" if is_root else "info"})
    return recs, None


_SYSLOG_RE = re.compile(r"^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s")
_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}


def _syslog_ts(line: str, year: int) -> str | None:
    m = _SYSLOG_RE.match(line)
    if not m:
        return None
    try:
        mon, day, hms = m.group(1).split(None, 2)
        h, mi, s = hms.split(":")
        return datetime(year, _MONTHS[mon], int(day), int(h), int(mi), int(s),
                        tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, KeyError):
        return None


def _parse_logs(d: Path) -> tuple[list[dict], str | None]:
    if not d.is_dir():
        return [], None
    recs: list[dict] = []
    interesting = re.compile(r"(sshd|sudo|authentication|Failed|screensharing|loginwindow)", re.IGNORECASE)
    for f in sorted(d.iterdir()):
        if not f.is_file() or "system.log" not in f.name:
            continue
        year = datetime.fromtimestamp(f.stat().st_mtime, tz=timezone.utc).year
        try:
            for line in f.read_text(errors="replace").splitlines():
                if not interesting.search(line):
                    continue
                ts = _syslog_ts(line, year)
                sev = "warn" if re.search(r"(Failed|failure|invalid)", line, re.IGNORECASE) else "info"
                recs.append({"timestamp": ts, "kind": "system.log",
                             "summary": line.split(":", 3)[-1].strip()[:200] if ":" in line else line[:200],
                             "detail": f.name, "severity": sev})
        except OSError:
            pass
    recs.sort(key=lambda r: r["timestamp"] or "", reverse=True)
    return recs, None


def _parse_unified_log(f: Path, limit: int = 40000) -> tuple[list[dict], str | None]:
    if not f.is_file():
        return [], None
    import json
    recs: list[dict] = []
    try:
        for i, line in enumerate(f.read_text(errors="replace").splitlines()):
            if i > limit:
                break
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            proc = (e.get("processImagePath") or "").rsplit("/", 1)[-1]
            msg = e.get("eventMessage") or ""
            raw = e.get("timestamp") or ""
            ts = None
            m = re.match(r"(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})", raw)
            if m:
                ts = f"{m.group(1)}T{m.group(2)}Z"
            sev = "warn" if re.search(r"(fail|denied|invalid)", msg, re.IGNORECASE) else "info"
            recs.append({"timestamp": ts, "kind": proc or "unified",
                         "summary": msg[:200], "detail": e.get("subsystem", ""), "severity": sev})
    except OSError as exc:
        return [], f"unified log ilegible: {exc}"
    recs.sort(key=lambda r: r["timestamp"] or "", reverse=True)
    return recs, None


def _findings(parsed: dict) -> list[dict]:
    f: list[dict] = []
    quar = len(parsed.get("quarantine", []))
    if quar:
        f.append({"level": "warn", "text": f"{quar} descarga(s) registrada(s) en cuarentena (Gatekeeper)"})
    crit_launchd = sum(1 for r in parsed.get("persistence", []) if r["severity"] == "crit")
    if crit_launchd:
        f.append({"level": "crit", "text": f"{crit_launchd} LaunchAgent/Daemon con rutas sospechosas (/tmp, curl, osascript…)"})
    user_launchd = sum(1 for r in parsed.get("persistence", []) if r["severity"] == "warn")
    if user_launchd:
        f.append({"level": "warn", "text": f"{user_launchd} LaunchAgent por usuario — revisa persistencia"})
    uid0 = sum(1 for r in parsed.get("accounts", []) if r["severity"] == "crit")
    if uid0:
        f.append({"level": "crit", "text": f"{uid0} cuenta(s) extra con UID 0"})
    susp = sum(1 for r in parsed.get("shell", []) if r["severity"] == "warn")
    if susp:
        f.append({"level": "warn", "text": f"{susp} comando(s) sospechoso(s) en el historial"})
    failed = sum(1 for cat in ("logs", "unified_log")
                 for r in parsed.get(cat, []) if r["severity"] == "warn")
    if failed:
        f.append({"level": "warn", "text": f"{failed} evento(s) de fallo de autenticación en los logs"})
    if not f:
        f.append({"level": "info", "text": "Sin hallazgos automáticos destacables — revisa la timeline"})
    return f


def parse(out_dir: Path, opts=None) -> tuple[dict, list[dict]]:
    art = out_dir / "artifacts"
    parsed: dict = {}
    errors: list[dict] = []

    def run(name, fn, *a):
        recs, err = fn(*a)
        parsed[name] = recs
        if err:
            errors.append({"parser": name, "error": err})
        log.info("[%s] %d registro(s)%s", name, len(recs), f" · aviso: {err}" if err else "")

    run("persistence", _parse_persistence, art / "persistence")
    run("shell", _parse_shell, art / "shell")
    run("browsers", _parse_browsers, art / "browsers")
    run("quarantine", _parse_quarantine, art / "quarantine")
    run("accounts", _parse_accounts, art / "accounts")
    run("logs", _parse_logs, art / "logs")
    run("unified_log", _parse_unified_log, art / "unified_log" / "unified_log.ndjson")
    parsed["_errors"] = errors
    return parsed, _findings(parsed)
