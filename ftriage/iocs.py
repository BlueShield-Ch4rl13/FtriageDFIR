"""Extracción de indicadores de compromiso (IOCs) desde los artefactos parseados.

Recorre todos los registros que producen los parsers, extrae IPs, dominios, URLs
y hashes, los deduplica con su recuento y los artefactos donde aparecen, y los
exporta defangueados. El formato de salida reutiliza la forma del pipeline de
News CTI ({value, type, ...}), de modo que estos IOCs se pueden reinyectar allí
para cruzarlos con la inteligencia de amenazas.
"""
from __future__ import annotations

import csv
import ipaddress
import json
import logging
import re
from pathlib import Path

log = logging.getLogger("ftriage")

# Expresiones para cada tipo de indicador
RE_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
RE_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
RE_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
RE_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
RE_URL = re.compile(r"\bhttps?://[^\s\"'<>]+", re.IGNORECASE)
RE_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:com|net|org|top|xyz|info|online|site|ru|cn|io|co|biz|club|shop|live|cc|lat|click|stream|download|link|host|ml|ga|cf|tk|gq)\b",
    re.IGNORECASE)

# Rutas de sistema legítimas que no son IOC de dominio útiles (falsos positivos)
_SKIP_DOMAINS = {"microsoft.com", "windows.com", "google.com", "mozilla.org",
                 "gstatic.com", "office.com", "live.com"}


def defang(value: str, kind: str) -> str:
    """Neutraliza el indicador para que no sea clicable en el informe."""
    if kind in ("ipv4", "domain", "url"):
        value = value.replace("http://", "hxxp://").replace("https://", "hxxps://")
        value = value.replace(".", "[.]")
    return value


def _iter_strings(obj):
    """Emite recursivamente todos los strings de un registro parseado."""
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _iter_strings(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from _iter_strings(v)


def _classify_ip(ip: str) -> tuple[bool, bool]:
    """(es_ip_válida, es_privada/reservada)."""
    try:
        obj = ipaddress.ip_address(ip)
        return True, (obj.is_private or obj.is_reserved or obj.is_loopback
                      or obj.is_link_local or obj.is_multicast)
    except ValueError:
        return False, False


def extract_iocs(parsed: dict) -> list[dict]:
    """Devuelve la lista de IOCs deduplicados con recuento, tipo y fuentes."""
    # value -> {type, count, sources:set, private}
    seen: dict[tuple[str, str], dict] = {}

    def add(value: str, kind: str, source: str, private: bool = False):
        key = (kind, value.lower() if kind in ("md5", "sha1", "sha256", "domain") else value)
        e = seen.get(key)
        if e is None:
            seen[key] = {"type": kind, "value": value, "count": 1,
                         "sources": {source}, "private": private}
        else:
            e["count"] += 1
            e["sources"].add(source)

    for category, records in parsed.items():
        if category == "_errors" or not isinstance(records, list):
            continue
        for rec in records:
            for s in _iter_strings(rec):
                # Hashes: comprobar de más largo a más corto para no solapar
                for m in RE_SHA256.findall(s):
                    add(m, "sha256", category)
                for m in RE_SHA1.findall(s):
                    add(m, "sha1", category)
                # MD5 solo si no forma parte de un hash más largo ya capturado
                for m in RE_MD5.findall(s):
                    if not RE_SHA1.search(s) and not RE_SHA256.search(s):
                        add(m, "md5", category)
                for m in RE_URL.findall(s):
                    add(m.rstrip(".,);"), "url", category)
                for m in RE_IPV4.findall(s):
                    valid, priv = _classify_ip(m)
                    if valid:
                        add(m, "ipv4", category, priv)
                for m in RE_DOMAIN.findall(s):
                    d = m.lower()
                    if d not in _SKIP_DOMAINS and not any(d.endswith("." + sk) for sk in _SKIP_DOMAINS):
                        add(d, "domain", category)

    out = []
    for e in seen.values():
        out.append({"type": e["type"], "value": e["value"],
                    "defanged": defang(e["value"], e["type"]),
                    "count": e["count"], "private": e["private"],
                    "sources": sorted(e["sources"])})
    # Externos primero, luego por frecuencia
    out.sort(key=lambda x: (x["private"], -x["count"], x["type"]))
    return out


def write_iocs(out_dir: Path, iocs: list[dict]) -> dict:
    """Exporta iocs.json (estructurado) e iocs.csv (defangueado)."""
    from datetime import datetime, timezone
    counts: dict[str, int] = {}
    for i in iocs:
        counts[i["type"]] = counts.get(i["type"], 0) + 1

    payload = {"generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
               "ioc_count": len(iocs), "counts_by_type": counts, "iocs": iocs}
    (out_dir / "iocs.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False),
                                       encoding="utf-8")
    with open(out_dir / "iocs.csv", "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["type", "value", "defanged", "count", "private", "sources"])
        for i in iocs:
            w.writerow([i["type"], i["value"], i["defanged"], i["count"],
                        i["private"], "; ".join(i["sources"])])
    ext = sum(1 for i in iocs if not i["private"])
    log.info("IOCs extraídos: %d (%d externos) → iocs.json, iocs.csv", len(iocs), ext)
    return {"total": len(iocs), "external": ext, "counts": counts}
