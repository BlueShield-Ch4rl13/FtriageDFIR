#!/usr/bin/env python3
"""ftriage — plataforma de triage forense y adquisición de imágenes (DFIR).

Uso exclusivamente defensivo (respuesta a incidentes). Dos subcomandos:

  triage   Recolecta artefactos del sistema (o de una imagen montada), calcula
           sus hashes (cadena de custodia), los parsea, extrae IOCs y genera un
           informe HTML navegable + JSON/NDJSON para SIEM.

  image    Crea una imagen forense bit a bit de un disco/dispositivo o fichero,
           con MD5+SHA256 y verificación, lista para Autopsy/X-Ways/FTK.

Ejemplos:
  # Triage del equipo vivo (como administrador/root), a un USB de evidencias:
  # la salida nunca va al disco que se investiga
  python triage.py triage --case IR-2026-014 --examiner "C. Villalba" --output E:\\IR-2026-014

  # Adquisición limpia con instantánea de volumen
  python triage.py triage --case IR-2026-014 --vss --output E:\\IR-2026-014

  # Reanalizar una carpeta ya recolectada
  python triage.py triage --parse-only .\\triage_DESKTOP_20260714

  # Imagen RAW de un disco, dividida en segmentos de 2 GB
  sudo python triage.py image --source /dev/sdb --output ./caso --case IR-2026-014 --split 2G

  # Imagen E01 (si libewf/ewfacquire está instalado)
  sudo python triage.py image --source /dev/sdb --output ./caso --format e01 --case IR-2026-014
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import hashlib
import hmac
import os

from ftriage import __version__, imaging, iocs, objetivo, platforms, reporting, utils, volatiles
from ftriage.utils import log


def _size_arg(s: str) -> int:
    """Convierte '2G', '512M', '100K' o un número en bytes."""
    s = s.strip().upper()
    mult = {"K": 1 << 10, "M": 1 << 20, "G": 1 << 30, "T": 1 << 40}
    if s and s[-1] in mult:
        return int(float(s[:-1]) * mult[s[-1]])
    return int(s)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="triage.py", description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version=f"ftriage {__version__}")
    sub = p.add_subparsers(dest="command")

    # ---- triage ----
    t = sub.add_parser("triage", help="Recolectar, parsear y generar informe")
    t.add_argument("--case", default="SIN-CASO", help="Identificador del caso")
    t.add_argument("--examiner", default="", help="Nombre del analista")
    t.add_argument("--desc", default="", help="Descripción breve del análisis (se muestra bajo el nombre del caso)")
    t.add_argument("--output", type=Path,
                   help="Carpeta de salida, en OTRO volumen que el investigado (obligatoria al recolectar)")
    t.add_argument("--allow-same-volume", action="store_true",
                   help="Permitir escribir en el mismo volumen que --root (contamina la evidencia)")
    t.add_argument("--no-volatiles", action="store_true",
                   help="En vivo, no recoger procesos/red/sesiones antes que los ficheros")
    t.add_argument("--root", type=Path, default=Path("C:\\") if utils.IS_WINDOWS else Path("/"),
                   help="Raíz del sistema (letra de una imagen montada para triage en frío)")
    t.add_argument("--target-os", default="auto", help="SO a triar: windows, linux, macos o auto (por defecto)")
    t.add_argument("--artifacts", default="all",
                   help="Categorías separadas por comas, o 'all' (dependen del --target-os)")
    t.add_argument("--vss", action="store_true", help="Adquirir vía instantánea VSS (Windows+admin)")
    t.add_argument("--ez-tools", type=Path, help="Carpeta con las EZ Tools (PECmd.exe)")
    t.add_argument("--collect-only", action="store_true", help="Solo recolectar")
    t.add_argument("--parse-only", type=Path, metavar="DIR", help="Reanalizar carpeta ya adquirida")
    t.add_argument("--no-iocs", action="store_true", help="No extraer IOCs")
    t.add_argument("--verbose", "-v", action="store_true", help="Log detallado")

    # ---- image ----
    im = sub.add_parser("image", help="Crear imagen forense de un disco/dispositivo")
    im.add_argument("--source", type=Path, required=True,
                    help="Dispositivo o fichero de origen (p. ej. /dev/sdb, \\\\.\\PhysicalDrive1)")
    im.add_argument("--output", type=Path, required=True, help="Carpeta destino de la imagen")
    im.add_argument("--case", default="SIN-CASO", help="Identificador del caso")
    im.add_argument("--examiner", default="", help="Nombre del analista")
    im.add_argument("--format", choices=["raw", "e01"], default="raw", help="Formato de imagen")
    im.add_argument("--split", type=_size_arg, default=0, metavar="TAM",
                    help="Dividir RAW en segmentos (p. ej. 2G, 650M)")
    im.add_argument("--block-size", type=_size_arg, default=1 << 20, help="Tamaño de bloque")
    im.add_argument("--no-verify", action="store_true", help="No verificar la imagen tras adquirir")
    im.add_argument("--reread-source", action="store_true",
                    help="Releer también el ORIGEN tras adquirir y comparar sus hashes (verificación completa)")
    im.add_argument("--verbose", "-v", action="store_true", help="Log detallado")
    return p


# ================================================================ triage
def cmd_triage(args) -> int:
    try:
        plat = platforms.select(args.target_os)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    opts = {"vss": getattr(args, "vss", False), "ez_tools": getattr(args, "ez_tools", None)}

    if args.parse_only:
        out_dir = args.parse_only
        if not (out_dir / "artifacts").is_dir():
            print(f"error: {out_dir} no contiene 'artifacts'", file=sys.stderr)
            return 2
        utils.setup_logging(out_dir / "triage.log", args.verbose)
        log.info("ftriage %s · reanálisis de %s (%s)", __version__, out_dir, plat.LABEL)
        mp = out_dir / "manifest.json"
        manifest = json.loads(mp.read_text(encoding="utf-8")) if mp.is_file() else []
    else:
        host_os = platforms.detect_host()
        target = platforms.normalize(args.target_os)
        en_vivo = objetivo.es_en_vivo(args.root, target, host_os)
        if args.output is None:
            print("error: indica --output en un volumen distinto del investigado (un USB de "
                  "evidencias o un recurso de red). Escribir en el propio disco sobrescribe "
                  "espacio libre y metadatos que forman parte de la evidencia.", file=sys.stderr)
            return 2
        out_dir = args.output
        if _mismo_volumen(out_dir, args.root) and not args.allow_same_volume:
            print(f"error: {out_dir} está en el mismo volumen que {args.root}. Usa otro volumen "
                  "o, a sabiendas, --allow-same-volume.", file=sys.stderr)
            return 2
        out_dir.mkdir(parents=True, exist_ok=True)
        utils.setup_logging(out_dir / "triage.log", args.verbose)
        log.info("ftriage %s · caso %s · objetivo: %s", __version__, args.case, plat.LABEL)
        log.info("Salida: %s", out_dir.resolve())
        if target != host_os and str(args.root) in ("/", "C:\\"):
            log.warning("Triando %s desde un host %s: apunta --root a la imagen montada", target, host_os)
        elif target == "windows" and utils.IS_WINDOWS and not utils.is_admin():
            log.warning("Sin privilegios de administrador: algunos artefactos bloqueados no se copiarán (considera --vss)")
        elif target in ("linux", "macos") and not utils.IS_WINDOWS and not utils.is_root():
            log.warning("Sin privilegios de root: algunos artefactos protegidos no se podrán copiar (usa sudo)")
        categories = _resolve_categories(args.artifacts, plat)
        manifest = []
        # RFC 3227: primero lo más volátil. Solo existe en el equipo vivo.
        if en_vivo and not args.no_volatiles:
            volatiles.recoger(target, out_dir, manifest)
        elif not en_vivo:
            log.info("Raíz %s montada: sin datos volátiles (no existen en una imagen)", args.root)
        manifest += plat.collect(args.root, out_dir, categories, opts)
        equipo = objetivo.describir(args.root, target, out_dir, en_vivo)
        (out_dir / "target.json").write_text(json.dumps(equipo, indent=2, ensure_ascii=False), encoding="utf-8")
        log.info("Equipo investigado: %s · %s (%s)", equipo.get("hostname"), equipo.get("os"), equipo.get("origen"))
        _guardar_manifiesto(out_dir, manifest)
        log.info("Cadena de custodia: manifest.json (+ manifest.json.sha256%s)",
                 " y .hmac" if os.environ.get("FTRIAGE_MANIFEST_KEY") else "")
        if args.collect_only:
            log.info("Modo --collect-only: sin parseo")
            return 0

    parsed, findings = plat.parse(out_dir, opts)

    ioc_summary = None
    found = []
    if not args.no_iocs:
        found = iocs.extract_iocs(parsed)
        ioc_summary = iocs.write_iocs(out_dir, found)

    tj = out_dir / "target.json"
    case = {"name": args.case, "examiner": args.examiner, "os": plat.LABEL,
            "description": args.desc, "generated_utc": utils.now_utc(),
            "host": json.loads(tj.read_text(encoding="utf-8")) if tj.is_file() else None}
    out = reporting.write_reports(out_dir, case, manifest, parsed, findings, found)
    _summary(out, ioc_summary)
    return 0


# ================================================================= image
def cmd_image(args) -> int:
    out_dir = args.output
    out_dir.mkdir(parents=True, exist_ok=True)
    utils.setup_logging(out_dir / "imaging.log", args.verbose)
    log.info("ftriage %s · adquisición de imagen · caso %s", __version__, args.case)
    case = {"name": args.case, "examiner": args.examiner}
    try:
        result = imaging.image_device(
            args.source, out_dir, case, fmt=args.format,
            block_size=args.block_size, split_bytes=args.split,
            verify=not args.no_verify, reread_source=args.reread_source)
    except (FileNotFoundError, PermissionError, OSError) as exc:
        log.error("Adquisición fallida: %s", exc)
        return 1
    log.info("=" * 52)
    h = result.get("hashes", {})
    log.info("Imagen creada · %s", ", ".join(Path(s).name for s in result.get("segments", [])))
    if h.get("md5"):
        log.info("  MD5   : %s", h["md5"])
    if h.get("sha256"):
        log.info("  SHA256: %s", h["sha256"])
    ver = result.get("verification") or ({"verified": result.get("verified")} if "verified" in result else None)
    if ver is not None:
        log.info("  Verificación: %s", "OK ✓" if ver.get("verified") else "FALLÓ ✗")
    log.info("=" * 52)
    return 0


# ================================================================= helpers
def _mismo_volumen(salida: Path, raiz: Path) -> bool:
    """True si la carpeta de salida está en el mismo sistema de ficheros que la raíz."""
    p = salida.resolve()
    while not p.exists() and p != p.parent:
        p = p.parent
    try:
        return os.stat(p).st_dev == os.stat(raiz).st_dev
    except OSError:
        return False


def _guardar_manifiesto(out_dir: Path, manifest: list[dict]) -> None:
    """manifest.json + su SHA-256 y, con FTRIAGE_MANIFEST_KEY, un HMAC.

    El .sha256 detecta un manifiesto dañado; solo el HMAC, con una clave que
    tiene el analista y no está en la carpeta del caso, impide que alguien
    edite el manifiesto y recalcule el hash.
    """
    datos = json.dumps(manifest, indent=2, ensure_ascii=False).encode("utf-8")
    (out_dir / "manifest.json").write_bytes(datos)
    (out_dir / "manifest.json.sha256").write_text(
        f"{hashlib.sha256(datos).hexdigest()}  manifest.json\n", encoding="utf-8")
    clave = os.environ.get("FTRIAGE_MANIFEST_KEY", "")
    if clave:
        firma = hmac.new(clave.encode("utf-8"), datos, hashlib.sha256).hexdigest()
        (out_dir / "manifest.json.hmac").write_text(f"HMAC-SHA256 {firma}\n", encoding="utf-8")


def _resolve_categories(value: str, plat) -> list[str]:
    cats = list(plat.CATEGORIES)
    if value.strip().lower() == "all":
        return cats
    chosen = [c.strip() for c in value.split(",") if c.strip()]
    invalid = [c for c in chosen if c not in cats]
    if invalid:
        log.error("Categorías no válidas para %s: %s (disponibles: %s)",
                  plat.LABEL, ", ".join(invalid), ", ".join(cats))
        sys.exit(2)
    return chosen


def _summary(out: dict, ioc_summary: dict | None) -> None:
    crit = sum(1 for f in out["findings"] if f["level"] == "crit")
    a = out.get("assessment") or {}
    log.info("=" * 52)
    if a:
        log.info("VEREDICTO: %s · riesgo %d/100 · confianza %s",
                 a.get("verdict", "?").upper(), a.get("risk_score", 0), a.get("confidence_tier", "?"))
        for r in a.get("reasons", [])[:4]:
            log.info("   → %s (%s, %s)", r["label"], r["attack"], r["tactic"])
    log.info("Informe listo · %d eventos en la timeline", out["timeline_events"])
    if ioc_summary:
        log.info("  IOCs: %d (%d externos)", ioc_summary["total"], ioc_summary["external"])
    if crit:
        log.info("  ⚠ %d hallazgo(s) crítico(s)", crit)
    log.info("  HTML  : %s", out["html"].resolve())
    log.info("  JSON  : %s", out["json"].resolve())
    log.info("  NDJSON: %s", out["ndjson"].resolve())
    log.info("=" * 52)


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    # Compatibilidad: si no se indica subcomando, asumir 'triage'
    if not argv or (argv[0] not in ("triage", "image") and argv[0] not in ("-h", "--help", "--version")):
        argv = ["triage"] + argv
    args = build_parser().parse_args(argv)
    if args.command == "image":
        return cmd_image(args)
    return cmd_triage(args)


if __name__ == "__main__":
    sys.exit(main())
