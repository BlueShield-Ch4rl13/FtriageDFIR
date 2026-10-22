"""Pruebas de la recolección, la cadena de custodia y la adquisición.

Todas trabajan sobre raíces falsas en tmp_path: nunca tocan el sistema real.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))

import triage  # noqa: E402
from ftriage import collectors, imaging, linux, macos, objetivo, utils  # noqa: E402


def escribir(ruta: Path, contenido: bytes | str) -> Path:
    ruta.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(contenido, str):
        contenido = contenido.encode()
    ruta.write_bytes(contenido)
    return ruta


# ------------------------------------------------------------- recolección
def test_los_ntuser_de_cada_usuario_no_se_pisan(tmp_path):
    root = tmp_path / "win"
    escribir(root / "Users" / "alice" / "NTUSER.DAT", b"colmena-de-alice")
    escribir(root / "Users" / "alice" / "NTUSER.DAT.LOG1", b"log-de-alice")
    escribir(root / "Users" / "bob" / "NTUSER.DAT", b"colmena-de-bob")
    out = tmp_path / "caso"
    manifest = collectors.Collector(root, out, ["registry"]).collect()
    copias = sorted(p.name for p in (out / "artifacts" / "registry").iterdir())
    assert copias == ["alice_NTUSER.DAT", "alice_NTUSER.DAT.LOG1", "bob_NTUSER.DAT"]
    assert (out / "artifacts" / "registry" / "alice_NTUSER.DAT").read_bytes() == b"colmena-de-alice"
    for m in manifest:
        assert (out / m["artifact"]).is_file(), "cada entrada del manifiesto apunta a una copia que existe"
        assert m["verified"] and m["source_sha256"] == m["sha256"]


def test_macos_launchdaemons_y_launchagents_con_el_mismo_nombre(tmp_path):
    root = tmp_path / "mac"
    escribir(root / "Library" / "LaunchDaemons" / "com.x.plist", b"daemon")
    escribir(root / "Library" / "LaunchAgents" / "com.x.plist", b"agent")
    escribir(root / "Users" / "ana" / "Library" / "LaunchAgents" / "com.x.plist", b"agent-de-ana")
    out = tmp_path / "caso"
    manifest = macos.collect(root, out, ["persistence"])
    nombres = sorted(Path(m["artifact"]).name for m in manifest if m["status"] == "ok")
    assert nombres == ["LaunchAgents_com.x.plist", "LaunchDaemons_com.x.plist", "ana_LaunchAgents_com.x.plist"]


def test_sqlite_en_modo_wal_se_copia_con_su_wal(tmp_path):
    root = tmp_path / "lin"
    perfil = root / "home" / "eva" / ".config" / "google-chrome" / "Default"
    escribir(perfil / "History", b"sqlite")
    escribir(perfil / "History-wal", b"lo-ultimo-que-se-visito")
    out = tmp_path / "caso"
    linux.collect(root, out, ["browsers"])
    copias = sorted(p.name for p in (out / "artifacts" / "browsers").iterdir())
    assert copias == ["eva_Default_History", "eva_Default_History-wal"]


def test_lastlog_disperso_no_se_copia(tmp_path):
    root = tmp_path / "lin"
    escribir(root / "var" / "log" / "wtmp", b"")
    lastlog = root / "var" / "log" / "lastlog"
    with open(lastlog, "wb") as f:              # aparenta 1 GB, ocupa casi nada
        f.truncate(1 << 30)
    nombres = [p.name for p, _ in linux._enumerate(root, "logins")]
    assert "wtmp" in nombres and "lastlog" not in nombres


def test_una_copia_que_no_coincide_con_el_original_se_marca(tmp_path, monkeypatch):
    origen = escribir(tmp_path / "evidencia" / "auth.log", b"linea 1\n")
    real = utils.copy_artifact

    def copia_y_cambia(src, dst_dir, shadow=None, dest_name=None):   # el log crece durante la copia
        r = real(src, dst_dir, shadow, dest_name)
        (dst_dir / (dest_name or src.name)).write_bytes(b"linea 1\nlinea 2\n")
        return r

    monkeypatch.setattr(utils, "copy_artifact", copia_y_cambia)
    manifest: list = []
    entrada = utils.copy_and_record("logs", origen, tmp_path / "caso" / "artifacts" / "logs", manifest)
    assert entrada["verified"] is False and "cambió" in entrada["note"]


# ------------------------------------------------------- equipo investigado
def test_el_equipo_sale_de_la_evidencia_y_no_del_analista(tmp_path):
    root = tmp_path / "imagen"
    escribir(root / "etc" / "hostname", "srv-dmz-01\n")
    escribir(root / "etc" / "os-release", 'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nVERSION_ID="12"\n')
    info = objetivo.describir(root, "linux", tmp_path / "caso", en_vivo=False)
    assert info["hostname"] == "srv-dmz-01"
    assert info["os"] == "Debian GNU/Linux 12 (bookworm)"
    assert "architecture" not in info, "nada de la estación del analista en una imagen montada"


# ----------------------------------------------------------------- triage
def _raiz_linux(tmp_path: Path) -> Path:
    root = tmp_path / "imagen"
    escribir(root / "etc" / "hostname", "srv-dmz-01\n")
    escribir(root / "etc" / "os-release", 'PRETTY_NAME="Debian GNU/Linux 12"\n')
    escribir(root / "var" / "log" / "auth.log", "Oct 22 10:00:00 srv sshd[1]: Failed password for root\n")
    return root


def test_sin_output_no_se_recolecta(tmp_path):
    root = _raiz_linux(tmp_path)
    assert triage.main(["triage", "--root", str(root), "--target-os", "linux", "--artifacts", "logs"]) == 2


def test_mismo_volumen_se_rechaza_salvo_que_se_pida(tmp_path):
    root = _raiz_linux(tmp_path)
    out = tmp_path / "salida"
    base = ["triage", "--root", str(root), "--target-os", "linux", "--artifacts", "logs",
            "--output", str(out), "--no-iocs"]
    assert triage.main(base) == 2, "tmp_path y la raíz falsa están en el mismo volumen"
    assert triage.main(base + ["--allow-same-volume"]) == 0
    informe = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert informe["host"]["hostname"] == "srv-dmz-01"
    assert "examiner_station" in informe, "la estación del analista va aparte, no como el equipo"
    assert informe["integrity"]["artifacts_verified"] == informe["integrity"]["artifacts_copied"] >= 1
    assert (out / "manifest.json.sha256").read_text().split()[0]


# --------------------------------------------------------------- imaging
def test_un_sector_malo_no_borra_el_bloque_entero(tmp_path, monkeypatch):
    origen = tmp_path / "disco.bin"
    datos = bytes(range(256)) * 32                      # 8 KiB
    origen.write_bytes(datos)
    malo = (4096, 4608)                                 # un solo sector ilegible
    leer = os.read

    def read_con_error(fd, n):
        pos = os.lseek(fd, 0, os.SEEK_CUR)
        if fd == estado["fd"] and pos < malo[1] and pos + n > malo[0]:
            raise OSError(5, "Input/output error")
        return leer(fd, n)

    abrir = os.open
    estado = {"fd": None}

    def open_y_recuerda(path, flags, *a):
        fd = abrir(path, flags, *a)
        if str(path) == str(origen):
            estado["fd"] = fd
        return fd

    monkeypatch.setattr(os, "open", open_y_recuerda)
    monkeypatch.setattr(os, "read", read_con_error)
    acq = imaging.acquire_raw(origen, tmp_path / "img" / "disco.dd", block_size=4096)
    monkeypatch.setattr(os, "read", leer)
    imagen = (tmp_path / "img" / "disco.dd").read_bytes()
    assert acq["bad_sectors"] == 1 and acq["bad_ranges"] == [malo]
    assert imagen[:4096] == datos[:4096] and imagen[4608:] == datos[4608:], "los sectores buenos del bloque se recuperan"
    assert imagen[4096:4608] == b"\x00" * 512


def test_relectura_del_origen(tmp_path):
    origen = tmp_path / "disco.bin"
    origen.write_bytes(os.urandom(64 * 1024))
    r = imaging.image_device(origen, tmp_path / "caso", {"name": "IR-1"}, block_size=8192, reread_source=True)
    assert r["verification"]["verified"] and r["verification"]["source_reread"]["verified"]


@pytest.mark.parametrize("raiz, objetivo_os, anfitrion, esperado", [
    (Path("/"), "linux", "linux", True),
    (Path("/mnt/imagen"), "linux", "linux", False),
    (Path("/"), "windows", "linux", False),
])
def test_en_vivo(raiz, objetivo_os, anfitrion, esperado):
    assert objetivo.es_en_vivo(raiz, objetivo_os, anfitrion) is esperado
