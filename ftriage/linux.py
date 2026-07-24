"""Plataforma Linux: recolección y parseo de artefactos forenses.

Artefactos cubiertos (categorías del flag --artifacts):
  logins       wtmp/btmp/lastlog — inicios de sesión correctos y fallidos
  logs         /var/log/auth.log|secure — SSH, sudo, sesiones
  journal      journald (vía journalctl) — sshd, sudo, arranque de servicios
  shell        historial de bash/zsh por usuario (comandos ejecutados)
  persistence  cron, unidades systemd, authorized_keys, ld.so.preload, rc.local
  accounts     /etc/passwd, sudoers — cuentas UID 0, shells, privilegios
  browsers     historial de Firefox/Chrome por usuario

Cada parser devuelve registros normalizados {timestamp, kind, summary, detail,
severity}. Tolerante a fallos: un fichero ilegible se registra y se sigue.
"""
from __future__ import annotations

import json
import logging
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from . import utils

log = logging.getLogger("ftriage")

LABEL = "Linux"
CATEGORIES = ["logins", "logs", "journal", "shell", "persistence", "accounts", "browsers"]

# Patrones que delatan una shell inversa o ejecución sospechosa en el historial
SUSPICIOUS_CMD = re.compile(
    r"(nc(?:\.traditional)?\s+.*-e|/dev/tcp/|bash\s+-i|python.*socket|"
    r"curl\s+.*\|\s*(?:bash|sh)|wget\s+.*\|\s*(?:sh|bash)|base64\s+-d|chmod\s+\+x)",
    re.IGNORECASE)


# ================================================================ recolección
def _homes(root: Path) -> list[Path]:
    homes = []
    h = root / "home"
    if h.is_dir():
        homes += [p for p in h.iterdir() if p.is_dir()]
    r = root / "root"
    if r.is_dir():
        homes.append(r)
    return homes


def _enumerate(root: Path, cat: str) -> list[tuple[Path, str | None]]:
    """(ruta_origen, nombre_destino) para una categoría; solo lo que existe."""
    r = root
    out: list[tuple[Path, str | None]] = []

    if cat == "logins":
        base = r / "var" / "log"
        out += [(base / n, None) for n in ("wtmp", "btmp", "lastlog")]

    elif cat == "logs":
        base = r / "var" / "log"
        for n in ("auth.log", "auth.log.1", "secure", "syslog", "messages", "cron"):
            out.append((base / n, None))
        out += [(p, None) for p in sorted(base.glob("secure-*"))]

    elif cat == "shell":
        for home in _homes(r):
            for n in (".bash_history", ".zsh_history", ".sh_history",
                      ".python_history", ".mysql_history"):
                f = home / n
                if f.exists():
                    out.append((f, f"{home.name}_{n.lstrip('.')}"))

    elif cat == "persistence":
        out.append((r / "etc" / "crontab", None))
        out.append((r / "etc" / "rc.local", None))
        out.append((r / "etc" / "ld.so.preload", None))
        for d in ("etc/cron.d", "etc/cron.daily", "etc/cron.hourly",
                  "var/spool/cron/crontabs", "var/spool/cron"):
            p = r / d
            if p.is_dir():
                out += [(f, f"{p.name}_{f.name}") for f in p.iterdir() if f.is_file()]
        sysd = r / "etc" / "systemd" / "system"
        if sysd.is_dir():
            out += [(f, None) for f in sorted(sysd.glob("*.service"))]
        for home in _homes(r):
            ak = home / ".ssh" / "authorized_keys"
            if ak.exists():
                out.append((ak, f"{home.name}_authorized_keys"))
            usd = home / ".config" / "systemd" / "user"
            if usd.is_dir():
                out += [(f, f"{home.name}_{f.name}") for f in usd.glob("*.service")]

    elif cat == "accounts":
        etc = r / "etc"
        out += [(etc / n, None) for n in ("passwd", "group", "shadow", "sudoers")]
        sd = etc / "sudoers.d"
        if sd.is_dir():
            out += [(f, f"sudoers.d_{f.name}") for f in sd.iterdir() if f.is_file()]

    elif cat == "browsers":
        for home in _homes(r):
            for vendor in ("google-chrome", "chromium", "microsoft-edge"):
                udata = home / ".config" / vendor
                if udata.is_dir():
                    for hist in udata.glob("*/History"):
                        out.append((hist, f"{home.name}_{hist.parent.name}_History"))
            ff = home / ".mozilla" / "firefox"
            if ff.is_dir():
                for places in ff.glob("*/places.sqlite"):
                    out.append((places, f"{home.name}_{places.parent.name}_places.sqlite"))

    return [(p, rn) for p, rn in out if p.exists()]


def _collect_journal(root: Path, dest_dir: Path, manifest: list) -> None:
    """Exporta el journal a JSON con journalctl (offline si root != /)."""
    import shutil
    if not shutil.which("journalctl"):
        log.info("[journal] journalctl no disponible (¿sistema sin systemd?)")
        return
    dest_dir.mkdir(parents=True, exist_ok=True)
    out_file = dest_dir / "journal.json"
    cmd = ["journalctl", "-o", "json", "--no-pager"]
    if str(root) != "/":
        jdir = root / "var" / "log" / "journal"
        if jdir.is_dir():
            cmd += ["-D", str(jdir)]
        else:
            return
    try:
        with open(out_file, "w", encoding="utf-8") as f:
            subprocess.run(cmd, stdout=f, stderr=subprocess.DEVNULL, timeout=600, check=False)
    except (subprocess.SubprocessError, OSError) as exc:
        log.warning("[journal] journalctl falló: %s", exc)
        return
    if out_file.exists() and out_file.stat().st_size:
        entry = {"category": "journal", "source": "journalctl -o json",
                 "collected_utc": utils.now_utc(), "status": "ok", "method": "journalctl",
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
        if cat == "journal":
            _collect_journal(root, art / "journal", manifest)
            continue
        sources = _enumerate(root, cat)
        if not sources:
            log.info("[%s] sin artefactos encontrados", cat)
            continue
        log.info("[%s] recolectando %d artefacto(s)", cat, len(sources))
        for src, rename in sources:
            utils.copy_and_record(cat, src, art / cat, manifest, rename)
    ok = sum(1 for e in manifest if e["status"] == "ok")
    log.info("Recolección Linux terminada: %d/%d artefactos", ok, len(manifest))
    return manifest


# ===================================================================== parseo
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


def _parse_logins(d: Path) -> tuple[list[dict], str | None]:
    if not d.is_dir():
        return [], None
    recs: list[dict] = []
    for name in ("wtmp", "btmp", "lastlog"):
        f = d / name
        if f.is_file():
            recs += utils.parse_utmp(f, failed=(name == "btmp"))
    recs.sort(key=lambda r: r["timestamp"] or "", reverse=True)
    return recs, None


def _parse_authlogs(d: Path) -> tuple[list[dict], str | None]:
    if not d.is_dir():
        return [], None
    recs: list[dict] = []
    re_ok = re.compile(r"Accepted (\w+) for (\S+) from (\S+)")
    re_fail = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+)")
    re_sudo = re.compile(r"sudo:\s+(\S+).*COMMAND=(.+)$")
    re_useradd = re.compile(r"useradd\[\d+\]:.*new user:\s*name=(\S+?),")
    for f in sorted(d.iterdir()):
        if not f.is_file() or not (f.name.startswith("auth") or f.name.startswith("secure")):
            continue
        year = datetime.fromtimestamp(f.stat().st_mtime, tz=timezone.utc).year
        try:
            for line in f.read_text(errors="replace").splitlines():
                ts = _syslog_ts(line, year)
                mo = re_ok.search(line)
                if mo:
                    method, user, ip = mo.groups()
                    recs.append({"timestamp": ts, "kind": "SSH correcto",
                                 "summary": f"{user}@{ip}", "detail": f"vía {method}",
                                 "severity": "warn" if user == "root" else "info"})
                    continue
                mf = re_fail.search(line)
                if mf:
                    user, ip = mf.groups()
                    recs.append({"timestamp": ts, "kind": "SSH fallido",
                                 "summary": f"{user}@{ip}", "detail": "contraseña incorrecta",
                                 "severity": "warn"})
                    continue
                ms = re_sudo.search(line)
                if ms:
                    who, cmd = ms.groups()
                    recs.append({"timestamp": ts, "kind": "sudo",
                                 "summary": cmd.strip()[:200], "detail": f"por {who}",
                                 "severity": "info"})
                    continue
                mu = re_useradd.search(line)
                if mu:
                    recs.append({"timestamp": ts, "kind": "usuario creado",
                                 "summary": mu.group(1), "detail": "useradd", "severity": "warn"})
        except OSError as exc:
            log.debug("auth log %s: %s", f.name, exc)
    recs.sort(key=lambda r: r["timestamp"] or "", reverse=True)
    return recs, None


def _parse_journal(f: Path, limit: int = 40000) -> tuple[list[dict], str | None]:
    if not f.is_file():
        return [], None
    recs: list[dict] = []
    interesting = {"sshd", "sudo", "su", "systemd-logind", "sshd-session"}
    try:
        for i, line in enumerate(f.read_text(errors="replace").splitlines()):
            if i > limit:
                break
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            ident = e.get("SYSLOG_IDENTIFIER") or e.get("_COMM") or ""
            msg = e.get("MESSAGE") or ""
            unit = e.get("_SYSTEMD_UNIT") or ""
            keep = ident in interesting or "authentication failure" in msg or \
                ("Started" in msg and unit.endswith(".service")) or \
                ("Failed" in msg and unit.endswith(".service"))
            if not keep:
                continue
            rt = e.get("__REALTIME_TIMESTAMP")
            ts = utils.unix_to_iso(int(rt) / 1_000_000) if rt else None
            sev = "warn" if ("fail" in msg.lower() or ident == "sudo") else "info"
            recs.append({"timestamp": ts, "kind": ident or "journal",
                         "summary": msg[:200], "detail": unit, "severity": sev})
    except OSError as exc:
        return [], f"journal ilegible: {exc}"
    recs.sort(key=lambda r: r["timestamp"] or "", reverse=True)
    return recs, None


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
        pending_ts = None
        for line in lines:
            if line.startswith(": ") and ";" in line:  # zsh extended history
                try:
                    epoch = int(line[2:].split(":", 1)[0])
                    pending_ts = utils.unix_to_iso(epoch)
                    line = line.split(";", 1)[1]
                except (ValueError, IndexError):
                    pass
            cmd = line.strip()
            if not cmd:
                continue
            recs.append({"timestamp": pending_ts, "kind": "comando",
                         "summary": cmd[:300], "detail": user,
                         "severity": "warn" if SUSPICIOUS_CMD.search(cmd) else "info"})
            pending_ts = None
    return recs, None


def _parse_persistence(d: Path) -> tuple[list[dict], str | None]:
    if not d.is_dir():
        return [], None
    recs: list[dict] = []
    re_exec = re.compile(r"ExecStart\s*=\s*(.+)")
    for f in sorted(d.iterdir()):
        if not f.is_file():
            continue
        ts = utils.file_mtime_iso(f)
        name = f.name
        try:
            content = f.read_text(errors="replace")
        except OSError:
            continue
        if name == "ld.so.preload":
            recs.append({"timestamp": ts, "kind": "ld.so.preload",
                         "summary": content.strip()[:200] or "(vacío)",
                         "detail": "precarga global de librerías — posible rootkit",
                         "severity": "crit"})
        elif name.endswith(".service"):
            for m in re_exec.finditer(content):
                recs.append({"timestamp": ts, "kind": "servicio systemd",
                             "summary": m.group(1).strip()[:250], "detail": name,
                             "severity": "info"})
        elif "authorized_keys" in name:
            for line in content.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    parts = line.split()
                    comment = parts[-1] if len(parts) >= 3 else ""
                    recs.append({"timestamp": ts, "kind": "authorized_key",
                                 "summary": comment or parts[0][:40], "detail": name,
                                 "severity": "warn"})
        else:  # cron / rc.local
            for line in content.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    recs.append({"timestamp": ts, "kind": "cron/rc",
                                 "summary": line[:250], "detail": name, "severity": "info"})
    recs.sort(key=lambda r: r["timestamp"] or "", reverse=True)
    return recs, None


def _parse_accounts(d: Path) -> tuple[list[dict], str | None]:
    if not d.is_dir():
        return [], None
    recs: list[dict] = []
    passwd = d / "passwd"
    if passwd.is_file():
        ts = utils.file_mtime_iso(passwd)
        try:
            for line in passwd.read_text(errors="replace").splitlines():
                parts = line.split(":")
                if len(parts) < 7:
                    continue
                name, _, uid, _, _, home, shell = parts[:7]
                login = shell.rsplit("/", 1)[-1] not in ("nologin", "false", "sync", "")
                is_root = uid == "0" and name != "root"
                if login or is_root:
                    recs.append({"timestamp": ts, "kind": "cuenta UID 0" if uid == "0" else "cuenta con shell",
                                 "summary": f"{name} (uid {uid})", "detail": f"{shell} · {home}",
                                 "severity": "crit" if is_root else "info"})
        except OSError:
            pass
    for sf in list(d.glob("sudoers*")):
        if not sf.is_file():
            continue
        ts = utils.file_mtime_iso(sf)
        try:
            for line in sf.read_text(errors="replace").splitlines():
                line = line.strip()
                if line and not line.startswith("#") and ("ALL" in line or "NOPASSWD" in line) \
                        and not line.startswith("Defaults"):
                    recs.append({"timestamp": ts, "kind": "regla sudoers",
                                 "summary": line[:200], "detail": sf.name,
                                 "severity": "warn" if "NOPASSWD" in line else "info"})
        except OSError:
            pass
    return recs, None


def _parse_browsers(d: Path) -> tuple[list[dict], str | None]:
    if not d.is_dir():
        return [], None
    recs: list[dict] = []
    for f in sorted(d.iterdir()):
        if not f.is_file():
            continue
        if "places.sqlite" in f.name:
            recs += utils.parse_firefox_history(f)
        elif "History" in f.name:
            recs += utils.parse_chromium_history(f)
    recs.sort(key=lambda r: r["timestamp"] or "", reverse=True)
    return recs, None


def _findings(parsed: dict, art: Path) -> list[dict]:
    f: list[dict] = []
    failed = sum(1 for r in parsed.get("logins", []) if r["kind"] == "acceso fallido") \
        + sum(1 for r in parsed.get("logs", []) if r["kind"] == "SSH fallido")
    if failed:
        f.append({"level": "warn", "text": f"{failed} inicio(s) de sesión SSH fallido(s)"})
    root_ssh = sum(1 for r in parsed.get("logs", []) if r["kind"] == "SSH correcto" and r["severity"] == "warn")
    if root_ssh:
        f.append({"level": "warn", "text": f"{root_ssh} acceso(s) SSH directo(s) como root"})
    uid0 = sum(1 for r in parsed.get("accounts", []) if r["severity"] == "crit")
    if uid0:
        f.append({"level": "crit", "text": f"{uid0} cuenta(s) extra con UID 0 — escalada/persistencia"})
    if (art / "persistence" / "ld.so.preload").exists():
        f.append({"level": "crit", "text": "Existe /etc/ld.so.preload — indicador clásico de rootkit"})
    susp = sum(1 for r in parsed.get("shell", []) if r["severity"] == "warn")
    if susp:
        f.append({"level": "warn", "text": f"{susp} comando(s) sospechoso(s) en el historial (shell inversa, descargas…)"})
    keys = sum(1 for r in parsed.get("persistence", []) if r["kind"] == "authorized_key")
    if keys:
        f.append({"level": "warn", "text": f"{keys} clave(s) SSH en authorized_keys — revisa accesos no autorizados"})
    nopass = sum(1 for r in parsed.get("accounts", []) if r["kind"] == "regla sudoers" and r["severity"] == "warn")
    if nopass:
        f.append({"level": "warn", "text": f"{nopass} regla(s) sudoers NOPASSWD"})
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

    run("logins", _parse_logins, art / "logins")
    run("logs", _parse_authlogs, art / "logs")
    run("journal", _parse_journal, art / "journal" / "journal.json")
    run("shell", _parse_shell, art / "shell")
    run("persistence", _parse_persistence, art / "persistence")
    run("accounts", _parse_accounts, art / "accounts")
    run("browsers", _parse_browsers, art / "browsers")
    parsed["_errors"] = errors
    return parsed, _findings(parsed, art)
