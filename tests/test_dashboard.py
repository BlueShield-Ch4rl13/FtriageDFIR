"""El panel publico (dfir.carlosvillalbalagos.com) y sus casos de ejemplo."""
from __future__ import annotations

import ipaddress
import re
import subprocess
import sys
from html.parser import HTMLParser
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
CASOS = [RAIZ / "casos" / f"ejemplo-{so}.json" for so in ("windows", "linux", "macos")]
DOCUMENTACION = [ipaddress.ip_network(r) for r in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


def test_index_html_es_lo_que_genera_build_dashboard(tmp_path):
    """index.html y app.js se publican tal cual: tienen que salir del generador, no editarse a mano."""
    salida = tmp_path / "index.html"
    subprocess.run([sys.executable, str(RAIZ / "build_dashboard.py"), *map(str, CASOS), str(salida)],
                   check=True, capture_output=True)
    for nombre in ("index.html", "app.js"):
        assert (tmp_path / nombre).read_text(encoding="utf-8") == (RAIZ / nombre).read_text(encoding="utf-8"), \
            f"{nombre} no esta al dia: python build_dashboard.py casos/ejemplo-{{windows,linux,macos}}.json index.html"


def test_sin_javascript_en_linea_y_csp_sin_unsafe_inline():
    """La CSP de dfir. no permite scripts en linea: ni <script> con codigo ni on...= en el HTML."""
    html = (RAIZ / "index.html").read_text(encoding="utf-8")
    # Con el analizador de HTML, no con expresiones regulares: ve <SCRIPT>, </script >
    # y atributos en cualquier orden igual que el navegador.
    class Etiquetas(HTMLParser):
        def __init__(self):
            super().__init__()
            self.scripts, self.manejadores = [], []

        def handle_starttag(self, tag, attrs):
            atributos = dict(attrs)
            if tag == "script":
                self.scripts.append(atributos)
            self.manejadores += [f"<{tag} {k}>" for k in atributos if k.startswith("on")]

    etiquetas = Etiquetas()
    etiquetas.feed(html)
    assert etiquetas.scripts, "index.html sin <script>"
    for atributos in etiquetas.scripts:
        assert atributos.get("src") == "app.js" or atributos.get("type") == "application/json", atributos
    assert not etiquetas.manejadores, f"manejadores en linea en index.html: {etiquetas.manejadores}"
    csp = next(l for l in (RAIZ / "_headers").read_text(encoding="utf-8").splitlines() if "Content-Security-Policy" in l)
    script_src = re.search(r"script-src([^;]*)", csp).group(1)
    assert "unsafe-inline" not in script_src and "unsafe-eval" not in script_src


def test_la_severidad_del_informe_no_se_pinta_como_html():
    """Un report.json manipulado podia meter HTML (y JavaScript) por el campo severity."""
    html = (RAIZ / "app.js").read_text(encoding="utf-8")
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
        assert not re.search(r"\b[\w-]+(?:\.|\[\.\])(?:top|xyz|ru|cn|tk)\b", texto), caso.name
        # Tampoco en la forma desactivada (91[.]219[.]236[.]14): antes se colaba por ahi
        for ip in set(re.findall(r"\b(?:\d{1,3}\[\.\]){3}\d{1,3}\b", texto)):
            dir_ = ipaddress.ip_address(ip.replace("[.]", "."))
            assert not dir_.is_global or any(dir_ in red for red in DOCUMENTACION), f"{caso.name}: {ip}"
