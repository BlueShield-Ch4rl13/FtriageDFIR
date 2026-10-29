"""El panel publico (dfir.carlosvillalbalagos.com) y sus casos de ejemplo."""
from __future__ import annotations

import ipaddress
import re
import subprocess
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
CASOS = [RAIZ / "casos" / f"ejemplo-{so}.json" for so in ("windows", "linux", "macos")]
DOCUMENTACION = [ipaddress.ip_network(r) for r in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


def test_index_html_es_lo_que_genera_build_dashboard(tmp_path):
    """index.html se publica tal cual: tiene que salir del generador, no editarse a mano."""
    salida = tmp_path / "index.html"
    subprocess.run([sys.executable, str(RAIZ / "build_dashboard.py"), *map(str, CASOS), str(salida)],
                   check=True, capture_output=True)
    assert salida.read_text(encoding="utf-8") == (RAIZ / "index.html").read_text(encoding="utf-8"), \
        "index.html no esta al dia: python build_dashboard.py casos/ejemplo-{windows,linux,macos}.json index.html"


def test_la_severidad_del_informe_no_se_pinta_como_html():
    """Un report.json manipulado podia meter HTML (y JavaScript) por el campo severity."""
    html = (RAIZ / "index.html").read_text(encoding="utf-8")
    funcion = re.search(r"function sevBadge\(s\)\{.*?\n", html).group(0)
    assert "hasOwnProperty.call(L,s)" in funcion and 's="info"' in funcion


def test_los_casos_de_ejemplo_no_acusan_a_ips_ni_dominios_reales():
    """Los casos se publican: el atacante va en rangos de documentacion (RFC 5737) y dominios .example."""
    for caso in CASOS:
        texto = caso.read_text(encoding="utf-8")
        for ip in set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", texto)):
            try:
                dir_ = ipaddress.ip_address(ip)
            except ValueError:
                continue
            assert not dir_.is_global or any(dir_ in red for red in DOCUMENTACION), f"{caso.name}: {ip}"
        assert not re.search(r"\b[\w-]+\.(?:top|xyz|ru|cn|tk)\b", texto), caso.name
