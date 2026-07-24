"""Adquisición forense de imágenes de disco.

Crea una copia bit a bit de un dispositivo (HDD/SSD, /dev/sdX, \\\\.\\PhysicalDriveN)
o de un fichero, con los hashes calculados durante la lectura y verificados después
releyendo la imagen. La salida es directamente ingerible en Autopsy, X-Ways o FTK:

  RAW (.dd/.001…)  copia cruda + fichero .info con metadatos y hashes; opción de
                   dividir en segmentos (--split) para transportar o FAT32.
  E01 (EnCase)     vía `ewfacquire` (libewf) si está instalado — formato preferido
                   por Autopsy: comprime, embebe hashes y metadatos del caso, y se
                   verifica con `ewfverify`.

Nota forense: la fuente debe estar protegida contra escritura (idealmente un
bloqueador hardware). La herramienta abre la fuente en solo lectura y nunca
escribe sobre ella, pero eso no sustituye a un write-blocker en un caso real.
"""
from __future__ import annotations

import ctypes
try:
    import fcntl  # solo disponible en sistemas Unix
except ImportError:  # Windows
    fcntl = None
import hashlib
import logging
import os
import shutil
import struct
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from . import utils

log = logging.getLogger("ftriage")

BLKGETSIZE64 = 0x80081272  # ioctl Linux: tamaño del dispositivo de bloque en bytes


def _device_size(fd: int, path: Path) -> int:
    """Tamaño en bytes de un fichero o dispositivo de bloque."""
    try:
        size = os.lseek(fd, 0, os.SEEK_END)
        os.lseek(fd, 0, os.SEEK_SET)
        if size > 0:
            return size
    except OSError:
        pass
    if utils.IS_WINDOWS or fcntl is None:  # dispositivos físicos: lseek/ioctl no fiables aquí
        return 0
    try:  # dispositivo de bloque en Linux: preguntar por ioctl
        buf = fcntl.ioctl(fd, BLKGETSIZE64, struct.pack("Q", 0))
        return struct.unpack("Q", buf)[0]
    except (OSError, AttributeError):
        return 0


def _fmt_duration(sec: float) -> str:
    m, s = divmod(int(sec), 60)
    h, m = divmod(m, 60)
    return f"{h:d}h{m:02d}m{s:02d}s" if h else f"{m:d}m{s:02d}s"


def acquire_raw(source: Path, image: Path, block_size: int = 1 << 20,
                split_bytes: int = 0, algos=("md5", "sha256"),
                progress_every: float = 5.0) -> dict:
    """Adquisición RAW con hashes en streaming y tolerancia a sectores dañados."""
    total = 0
    hs = {a: hashlib.new(a) for a in algos}
    bad_ranges: list[tuple[int, int]] = []
    seg_index = 0
    seg_written = 0
    image.parent.mkdir(parents=True, exist_ok=True)

    def open_segment(i: int):
        # Sin división: nombre tal cual. Con división: .001, .002, …
        p = image if not split_bytes else image.with_suffix(image.suffix + f".{i+1:03d}")
        return p, open(p, "wb")

    src_fd = os.open(source, os.O_RDONLY | (getattr(os, "O_BINARY", 0)))
    size = _device_size(src_fd, source)
    seg_path, out = open_segment(seg_index)
    segments = [seg_path]
    start = time.time()
    last = start
    log.info("Imaging RAW de %s (%s)%s", source,
             utils.human_size(size) if size else "tamaño desconocido",
             f" en segmentos de {utils.human_size(split_bytes)}" if split_bytes else "")
    try:
        offset = 0
        while True:
            try:
                chunk = os.read(src_fd, block_size)
            except OSError as exc:  # sector defectuoso: rellenar con ceros y seguir
                log.warning("Error de lectura en offset %d: %s (relleno con ceros)", offset, exc)
                chunk = b"\x00" * block_size
                bad_ranges.append((offset, offset + block_size))
                try:
                    os.lseek(src_fd, offset + block_size, os.SEEK_SET)
                except OSError:
                    break
            if not chunk:
                break
            # Rotar segmento si toca
            if split_bytes and seg_written + len(chunk) > split_bytes:
                out.close()
                seg_index += 1
                seg_path, out = open_segment(seg_index)
                segments.append(seg_path)
                seg_written = 0
            out.write(chunk)
            for h in hs.values():
                h.update(chunk)
            n = len(chunk)
            total += n
            seg_written += n
            offset += n
            now = time.time()
            if now - last >= progress_every:
                pct = f"{total*100/size:.1f}%" if size else "?"
                rate = total / (now - start) / (1 << 20)
                log.info("  %s copiado (%s) · %.1f MB/s", utils.human_size(total), pct, rate)
                last = now
    finally:
        out.close()
        os.close(src_fd)

    elapsed = time.time() - start
    digests = {a: h.hexdigest() for a, h in hs.items()}
    log.info("Adquisición terminada: %s en %s", utils.human_size(total), _fmt_duration(elapsed))
    return {
        "format": "raw", "bytes": total, "duration_s": round(elapsed, 1),
        "segments": [str(s) for s in segments], "hashes": digests,
        "bad_sectors": len(bad_ranges), "bad_ranges": bad_ranges[:100],
        "block_size": block_size, "split_bytes": split_bytes,
    }


def verify_raw(segments: list[Path], expected: dict, algos=("md5", "sha256"),
               block_size: int = 1 << 20) -> dict:
    """Relee la imagen escrita y comprueba que sus hashes coinciden con el origen."""
    hs = {a: hashlib.new(a) for a in algos}
    for seg in segments:
        with open(seg, "rb") as f:
            for block in iter(lambda: f.read(block_size), b""):
                for h in hs.values():
                    h.update(block)
    got = {a: h.hexdigest() for a, h in hs.items()}
    ok = all(got.get(a) == expected.get(a) for a in algos)
    log.info("Verificación de la imagen: %s", "OK ✓ (hashes coinciden)" if ok else "FALLÓ ✗")
    return {"verified": ok, "image_hashes": got}


def acquire_e01(source: Path, image: Path, case: dict,
                compression: str = "fast") -> dict | None:
    """Adquisición E01 con ewfacquire (libewf). None si no está instalado."""
    ewf = shutil.which("ewfacquire")
    if not ewf:
        return None
    target = str(image.with_suffix(""))  # ewfacquire añade .E01
    cmd = [ewf, "-u", "-t", target, "-f", "encase6", "-c", f"deflate:{compression}",
           "-d", "sha256", "-C", case.get("name", "case"),
           "-E", case.get("examiner", "-") or "-",
           "-D", "ftriage acquisition", "-e", case.get("examiner", "-") or "-",
           "-m", "removable", "-M", "logical", str(source)]
    log.info("Imaging E01 con ewfacquire → %s.E01", target)
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=86400)
    except (FileNotFoundError, subprocess.SubprocessError) as exc:
        log.warning("ewfacquire falló: %s", exc)
        return None
    if res.returncode != 0:
        log.warning("ewfacquire devolvió error: %s", res.stderr.strip()[:400])
        return None
    out_file = Path(f"{target}.E01")
    result = {"format": "e01", "segments": [str(out_file)],
              "bytes": out_file.stat().st_size if out_file.exists() else 0,
              "hashes": _parse_ewf_hashes(res.stdout)}
    # Verificación con ewfverify si está disponible
    ewfv = shutil.which("ewfverify")
    if ewfv:
        try:
            v = subprocess.run([ewfv, "-d", "sha256", f"{target}.E01"],
                               capture_output=True, text=True, timeout=86400)
            result["verified"] = v.returncode == 0
            log.info("Verificación E01 (ewfverify): %s", "OK ✓" if v.returncode == 0 else "FALLÓ ✗")
        except subprocess.SubprocessError:
            result["verified"] = None
    return result


def _parse_ewf_hashes(output: str) -> dict:
    """Extrae MD5/SHA256 de la salida de ewfacquire."""
    hashes = {}
    for line in output.splitlines():
        low = line.lower()
        if "md5 hash calculated over data:" in low:
            hashes["md5"] = line.split(":")[-1].strip()
        elif "sha256 hash calculated over data:" in low:
            hashes["sha256"] = line.split(":")[-1].strip()
    return hashes


def write_info(image: Path, source: Path, case: dict, acq: dict,
               verify: dict | None) -> Path:
    """Escribe el .info (texto + JSON) con metadatos y hashes, junto a la imagen."""
    now = utils.now_utc()
    host = utils.host_info()
    hashes = acq.get("hashes", {})
    lines = [
        "=" * 60,
        " INFORME DE ADQUISICIÓN FORENSE (ftriage)",
        "=" * 60,
        f" Caso            : {case.get('name','-')}",
        f" Analista        : {case.get('examiner','-')}",
        f" Fecha (UTC)     : {now}",
        f" Estación        : {host['hostname']} · {host['os']}",
        "",
        f" Origen          : {source}",
        f" Imagen          : {', '.join(Path(s).name for s in acq.get('segments', []))}",
        f" Formato         : {acq.get('format','raw').upper()}",
        f" Tamaño          : {acq.get('bytes',0)} bytes ({utils.human_size(acq.get('bytes',0))})",
        f" Duración        : {_fmt_duration(acq.get('duration_s',0))}",
        f" Sectores dañados: {acq.get('bad_sectors',0)}",
        "",
        " HASHES DE LA ADQUISICIÓN",
    ]
    for algo in ("md5", "sha1", "sha256"):
        if hashes.get(algo):
            lines.append(f"   {algo.upper():7}: {hashes[algo]}")
    if verify is not None:
        lines += ["", f" VERIFICACIÓN    : {'OK - la imagen coincide con el origen' if verify.get('verified') else 'FALLÓ - los hashes NO coinciden'}"]
        for algo, val in verify.get("image_hashes", {}).items():
            lines.append(f"   {algo.upper():7}(imagen): {val}")
    lines += ["", " Generado por ftriage · uso exclusivamente para respuesta a incidentes.", "=" * 60, ""]

    txt = image.with_suffix(image.suffix + ".info.txt")
    txt.write_text("\n".join(lines), encoding="utf-8")

    import json
    info = {"case": case, "host": host, "acquired_utc": now, "source": str(source),
            "acquisition": {k: v for k, v in acq.items() if k != "bad_ranges"},
            "verification": verify}
    image.with_suffix(image.suffix + ".info.json").write_text(
        json.dumps(info, indent=2, ensure_ascii=False), encoding="utf-8")
    log.info("Metadatos de adquisición: %s", txt.name)
    return txt


def image_device(source: Path, out_dir: Path, case: dict, fmt: str = "raw",
                 block_size: int = 1 << 20, split_bytes: int = 0,
                 verify: bool = True, algos=("md5", "sha256")) -> dict:
    """Orquesta la adquisición completa: imagen + hashes + verificación + .info."""
    source = Path(source)
    if not source.exists():
        raise FileNotFoundError(f"origen no encontrado: {source}")
    if not utils.IS_WINDOWS and os.geteuid() != 0 and _is_block_device(source):
        log.warning("Imaging de un dispositivo sin root: probablemente falle (usa sudo)")
    log.warning("Asegúrate de que el origen está protegido contra escritura (write-blocker)")

    out_dir.mkdir(parents=True, exist_ok=True)
    stem = f"{case.get('name','image').replace('/', '-')}_{source.name}"

    if fmt == "e01":
        image = out_dir / f"{stem}.E01"
        acq = acquire_e01(source, image, case)
        if acq is None:
            log.warning("E01 no disponible (falta ewfacquire/libewf); usando RAW")
            fmt = "raw"
        else:
            write_info(image, source, case, acq, {"verified": acq.get("verified")} if "verified" in acq else None)
            return acq

    image = out_dir / f"{stem}.dd"
    acq = acquire_raw(source, image, block_size, split_bytes, algos)
    ver = None
    if verify:
        ver = verify_raw([Path(s) for s in acq["segments"]], acq["hashes"], algos, block_size)
    write_info(image, source, case, acq, ver)
    return {**acq, "verification": ver}


def _is_block_device(p: Path) -> bool:
    try:
        import stat
        return stat.S_ISBLK(os.stat(p).st_mode)
    except OSError:
        return False
