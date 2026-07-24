"""Construcción de los informes a partir de los datos parseados.

Tres salidas complementarias:
  report.json     informe completo estructurado (metadatos, cadena de custodia,
                  hallazgos y todos los artefactos parseados)
  timeline.ndjson una línea JSON por observación con timestamp, lista para
                  ingerir en un SIEM (Splunk/Elastic/Sentinel)
  report.html     informe autocontenido y navegable; su pieza central es la
                  super-timeline que fusiona todos los artefactos en un único
                  eje temporal — la vista con la que se empieza un análisis DFIR

El HTML no hace ninguna petición externa: estilos y lógica van embebidos y las
tablas se renderizan en el propio fichero.
"""
from __future__ import annotations

import html
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from . import utils

log = logging.getLogger("ftriage")

# Eventos que merecen resaltarse en rojo (borrado de logs, detecciones AV)
CRITICAL_EVENTS = {"1102", "104", "1116", "1117"}
# Eventos que merecen atención (fallos de acceso, persistencia, ejecución)
WARN_EVENTS = {"4625", "7045", "4720", "4728", "4732", "4756", "4104", "4688"}

# Metadatos por categoría de artefacto (todas las plataformas): etiqueta + color.
# Las categorías "rich" (Windows) tienen tabla propia; el resto usa tabla genérica.
CATEGORY_META = {
    # Windows (tablas a medida)
    "eventlogs": ("Eventos", "#6EA8FE"), "prefetch": ("Prefetch", "#E0A34A"),
    "amcache": ("Amcache", "#A6E22E"), "shimcache": ("Shimcache", "#C77DFF"),
    "browsers": ("Navegador", "#4DD0C4"),
    # Linux / macOS (tabla genérica a partir de timestamp/kind/summary/detail)
    "logins": ("Accesos", "#6EA8FE"), "logs": ("Logs", "#E0A34A"),
    "journal": ("Journal", "#4DD0C4"), "shell": ("Shell", "#A6E22E"),
    "persistence": ("Persistencia", "#F0616D"), "accounts": ("Cuentas", "#C77DFF"),
    "quarantine": ("Cuarentena", "#F0616D"), "unified_log": ("Unified Log", "#4DD0C4"),
}
RICH_CATEGORIES = {"eventlogs", "prefetch", "amcache", "shimcache", "browsers"}

# Color de cada fuente en la super-timeline (nombres tal como se usan en la timeline)
SOURCE_COLORS = {
    "Evento": "#6EA8FE", "Prefetch": "#E0A34A", "Amcache": "#A6E22E",
    "Shimcache": "#C77DFF", "Navegador": "#4DD0C4",
}
SOURCE_COLORS.update({label: color for label, color in CATEGORY_META.values()})


# ============================================================ super-timeline
def build_timeline(parsed: dict) -> list[dict]:
    """Fusiona todos los artefactos con timestamp en un único eje temporal."""
    tl: list[dict] = []

    for e in parsed.get("eventlogs", []):
        det = " · ".join(f"{k}={v}" for k, v in (e.get("details") or {}).items())
        sev = "crit" if e["event_id"] in CRITICAL_EVENTS else \
              "warn" if e["event_id"] in WARN_EVENTS else "info"
        tl.append({"timestamp": e["timestamp"], "source": "Evento",
                   "type": f"EID {e['event_id']}", "summary": e["description"],
                   "detail": det or e.get("channel", ""), "severity": sev})

    for p in parsed.get("prefetch", []):
        rc = p.get("run_count")
        tl.append({"timestamp": p["timestamp"], "source": "Prefetch",
                   "type": "Ejecución",
                   "summary": p["executable"] + (f" (x{rc})" if rc else ""),
                   "detail": p.get("source_pf", ""), "severity": "info"})

    for a in parsed.get("amcache", []):
        tl.append({"timestamp": a["timestamp"], "source": "Amcache",
                   "type": "Programa", "summary": a["path"],
                   "detail": (f"SHA1 {a['sha1']}" if a.get("sha1") else "")
                             + (f" · {a['publisher']}" if a.get("publisher") else ""),
                   "severity": "info"})

    for s in parsed.get("shimcache", []):
        tl.append({"timestamp": s["timestamp"], "source": "Shimcache",
                   "type": "Presencia", "summary": s["path"],
                   "detail": f"orden #{s.get('order', '?')}", "severity": "info"})

    for b in parsed.get("browsers", []):
        tl.append({"timestamp": b["timestamp"], "source": "Navegador",
                   "type": b.get("kind", "visita"),
                   "summary": b.get("url") or b.get("summary", ""),
                   "detail": b.get("title") or b.get("detail", ""), "severity": "info"})

    # Categorías genéricas (Linux/macOS): registros con campos normalizados
    for cat, records in parsed.items():
        if cat in RICH_CATEGORIES or cat == "_errors" or not isinstance(records, list):
            continue
        label = CATEGORY_META.get(cat, (cat.title(), "#8B97A5"))[0]
        for r in records:
            tl.append({"timestamp": r.get("timestamp"), "source": label,
                       "type": r.get("kind", ""), "summary": r.get("summary", ""),
                       "detail": r.get("detail", ""), "severity": r.get("severity", "info")})

    # Solo observaciones con timestamp, de más reciente a más antigua
    tl = [t for t in tl if t["timestamp"]]
    tl.sort(key=lambda t: t["timestamp"], reverse=True)
    return tl


def build_findings(parsed: dict, manifest: list[dict]) -> list[dict]:
    """Hallazgos automáticos que orientan por dónde empezar a mirar."""
    findings: list[dict] = []
    events = parsed.get("eventlogs", [])

    def count(eid): return sum(1 for e in events if e["event_id"] == eid)

    cleared = count("1102") + count("104")
    if cleared:
        findings.append({"level": "crit", "text":
                         f"{cleared} evento(s) de borrado de registros — posible anti-forense"})
    defender = count("1116") + count("1117")
    if defender:
        findings.append({"level": "crit", "text":
                         f"{defender} detección(es) de Windows Defender"})
    failed = count("4625")
    if failed:
        findings.append({"level": "warn", "text":
                         f"{failed} inicio(s) de sesión fallido(s) (EID 4625)"})
    svc = count("7045")
    if svc:
        findings.append({"level": "warn", "text":
                         f"{svc} servicio(s) instalado(s) (EID 7045) — vector de persistencia"})
    psh = count("4104")
    if psh:
        findings.append({"level": "warn", "text":
                         f"{psh} bloque(s) de script de PowerShell registrados (EID 4104)"})
    new_users = count("4720")
    if new_users:
        findings.append({"level": "warn", "text":
                         f"{new_users} cuenta(s) de usuario creada(s) (EID 4720)"})
    failed_copy = sum(1 for m in manifest if m["status"] != "ok")
    if failed_copy:
        findings.append({"level": "warn", "text":
                         f"{failed_copy} artefacto(s) no se pudieron adquirir (revisa la cadena de custodia)"})
    if not findings:
        findings.append({"level": "info", "text":
                         "Sin hallazgos automáticos destacables — revisa la timeline manualmente"})
    return findings


# =================================================================== JSON
def write_json(out_dir: Path, case: dict, manifest: list[dict],
               parsed: dict, timeline: list[dict], findings: list[dict],
               assessment: dict | None = None, iocs: list[dict] | None = None) -> Path:
    verified = sum(1 for m in manifest if m.get("sha256"))
    report = {
        "case": case,
        "host": utils.host_info(),
        "generated_utc": utils.now_utc(),
        "assessment": assessment or {},
        "iocs": iocs or [],
        "integrity": {"artifacts_total": len(manifest), "artifacts_hashed": verified},
        "findings": findings,
        "chain_of_custody": manifest,
        "artifacts": {k: v for k, v in parsed.items() if k != "_errors"},
        "parse_errors": parsed.get("_errors", []),
        "timeline_count": len(timeline),
        "timeline": timeline,
    }
    path = out_dir / "report.json"
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    # NDJSON: una observación por línea para el SIEM
    nd = out_dir / "timeline.ndjson"
    with open(nd, "w", encoding="utf-8") as f:
        host = utils.host_info().get("hostname", "")
        for row in timeline:
            f.write(json.dumps({**row, "host": host}, ensure_ascii=False) + "\n")
    log.info("Escritos report.json y timeline.ndjson (%d eventos)", len(timeline))
    return path


# =================================================================== HTML
def _esc(v) -> str:
    return html.escape(str(v)) if v is not None else ""


def _table(headers: list[str], rows: list[list], table_id: str,
           row_classes: list[str] | None = None) -> str:
    """Genera una tabla filtrable/ordenable (la lógica JS es común a todas)."""
    thead = "".join(
        f'<th onclick="sortTable(\'{table_id}\',{i})">{_esc(h)}<span class="ar"></span></th>'
        for i, h in enumerate(headers))
    body = []
    for r, row in enumerate(rows):
        cls = f' class="{row_classes[r]}"' if row_classes else ""
        cells = "".join(f"<td>{c}</td>" for c in row)  # celdas ya escapadas
        body.append(f"<tr{cls}>{cells}</tr>")
    return (
        f'<div class="tablewrap">'
        f'<input class="filter" placeholder="Filtrar…" '
        f'oninput="filterTable(\'{table_id}\',this.value)">'
        f'<div class="scroll"><table id="{table_id}"><thead><tr>{thead}</tr></thead>'
        f'<tbody>{"".join(body)}</tbody></table></div></div>'
    )


def _fmt_ts(ts: str | None) -> str:
    """ISO -> 'YYYY-MM-DD HH:MM:SS' para lectura."""
    if not ts:
        return "—"
    return _esc(ts.replace("T", " ").rstrip("Z"))


def _mono(v) -> str:
    return f'<span class="mono">{_esc(v)}</span>' if v else "—"


def _sev_badge(sev: str) -> str:
    label = {"crit": "crítico", "warn": "atención", "info": "info"}.get(sev, sev)
    return f'<span class="sev sev-{sev}">{label}</span>'


def write_html(out_dir: Path, case: dict, manifest: list[dict],
               parsed: dict, timeline: list[dict], findings: list[dict],
               tl_limit: int = 1500, tbl_limit: int = 800) -> Path:
    host = utils.host_info()
    verified = sum(1 for m in manifest if m.get("sha256"))
    counts = {k: len(parsed.get(k, [])) for k in
              ("eventlogs", "prefetch", "amcache", "shimcache", "browsers")}

    # -- Timeline (hero) --
    tl_rows, tl_cls = [], []
    for t in timeline[:tl_limit]:
        color = SOURCE_COLORS.get(t["source"], "#8B97A5")
        marker = f'<span class="dot" style="background:{color}"></span>'
        tl_rows.append([
            f'{marker}<span class="mono nowrap">{_fmt_ts(t["timestamp"])}</span>',
            f'<span class="src" style="color:{color}">{_esc(t["source"])}</span>',
            _esc(t["type"]),
            f'<span class="mono wrap">{_esc(t["summary"])}</span>',
            f'<span class="muted wrap">{_esc(t["detail"])}</span>',
        ])
        tl_cls.append(f'row-{t["severity"]}')
    timeline_tbl = _table(
        ["Fecha (UTC)", "Fuente", "Tipo", "Detalle", "Contexto"],
        tl_rows, "tl", tl_cls)

    # -- Tablas por artefacto --
    ev_rows, ev_cls = [], []
    for e in parsed.get("eventlogs", [])[:tbl_limit]:
        sev = "crit" if e["event_id"] in CRITICAL_EVENTS else \
              "warn" if e["event_id"] in WARN_EVENTS else "info"
        det = " · ".join(f"{k}={v}" for k, v in (e.get("details") or {}).items())
        ev_rows.append([_mono(_fmt_ts(e["timestamp"])), _mono(e["event_id"]),
                        _sev_badge(sev), _esc(e["description"]),
                        f'<span class="mono">{_esc(e.get("log_file",""))}</span>',
                        f'<span class="wrap">{_esc(det)}</span>'])
        ev_cls.append(f"row-{sev}")
    events_tbl = _table(["Fecha (UTC)", "EID", "Sev.", "Descripción", "Log", "Datos"],
                        ev_rows, "ev", ev_cls)

    pf_rows = [[_mono(_fmt_ts(p["timestamp"])), f'<span class="mono">{_esc(p["executable"])}</span>',
                _esc(p.get("run_count") or 0),
                f'<span class="muted mono">{_esc(", ".join(p.get("previous_runs", [])[:4]))}</span>']
               for p in parsed.get("prefetch", [])[:tbl_limit]]
    prefetch_tbl = _table(["Última ejecución (UTC)", "Ejecutable", "Nº", "Ejecuciones previas"],
                          pf_rows, "pf")

    am_rows = [[_mono(_fmt_ts(a["timestamp"])),
                f'<span class="mono wrap">{_esc(a["path"])}</span>',
                f'<span class="mono">{_esc(a.get("sha1",""))}</span>',
                _esc(a.get("publisher", ""))]
               for a in parsed.get("amcache", [])[:tbl_limit]]
    amcache_tbl = _table(["Modificado (UTC)", "Ruta", "SHA-1", "Editor"], am_rows, "am")

    sh_rows = [[_esc(s.get("order", "")), _mono(_fmt_ts(s.get("last_modified"))),
                f'<span class="mono wrap">{_esc(s["path"])}</span>']
               for s in parsed.get("shimcache", [])[:tbl_limit]]
    shimcache_tbl = _table(["Orden", "Modificado (UTC)", "Ruta"], sh_rows, "sh")

    br_rows = [[_mono(_fmt_ts(b["timestamp"])), _esc(b.get("kind", "")),
                f'<span class="mono wrap">{_esc(b.get("url") or b.get("summary",""))}</span>',
                f'<span class="wrap">{_esc(b.get("title") or b.get("detail",""))}</span>',
                _esc(b.get("visit_count", ""))]
               for b in parsed.get("browsers", [])[:tbl_limit]]
    browsers_tbl = _table(["Fecha (UTC)", "Tipo", "URL/recurso", "Título", "Visitas"],
                          br_rows, "br")

    RICH_TABS = {"eventlogs": events_tbl, "prefetch": prefetch_tbl, "amcache": amcache_tbl,
                 "shimcache": shimcache_tbl, "browsers": browsers_tbl}

    # -- Cadena de custodia --
    coc_rows, coc_cls = [], []
    for m in manifest:
        sha = m.get("sha256") or ""
        md5 = m.get("md5") or ""
        sha_cell = (f'<span class="mono hash" title="{sha}">{sha[:16]}…</span>'
                    if sha else '<span class="muted">—</span>')
        md5_cell = (f'<span class="mono hash" title="{md5}">{md5[:12]}…</span>'
                    if md5 else '<span class="muted">—</span>')
        status_ok = m["status"] == "ok"
        coc_rows.append([
            _esc(m["category"]),
            f'<span class="mono wrap">{_esc(m["source"])}</span>',
            f'<span class="mono">{_esc(m.get("method","—"))}</span>',
            _esc(utils.human_size(m["size"])) if m.get("size") else "—",
            md5_cell,
            sha_cell,
            f'<span class="sev sev-{"info" if status_ok else "crit"}">{_esc(m["status"])}</span>',
        ])
        coc_cls.append("" if status_ok else "row-crit")
    coc_tbl = _table(["Categoría", "Origen", "Método", "Tamaño", "MD5", "SHA-256", "Estado"],
                     coc_rows, "coc", coc_cls)

    # -- Piezas de cabecera --
    findings_html = "".join(
        f'<li class="f-{f["level"]}">{_esc(f["text"])}</li>' for f in findings)

    # Pestañas dinámicas: solo las categorías presentes, en el orden de CATEGORY_META.
    # Las "rich" (Windows) usan su tabla a medida; el resto, tabla genérica.
    tabs = [("timeline", "Timeline", timeline_tbl)]
    card_items = []
    for cat, (label, _color) in CATEGORY_META.items():
        records = parsed.get(cat)
        if not records:
            continue
        card_items.append((label, len(records)))
        if cat in RICH_TABS:
            tabs.append((cat, label, RICH_TABS[cat]))
        else:
            rows = [[_mono(_fmt_ts(r.get("timestamp"))), _esc(r.get("kind", "")),
                     f'<span class="mono wrap">{_esc(r.get("summary",""))}</span>',
                     f'<span class="wrap">{_esc(r.get("detail",""))}</span>']
                    for r in records[:tbl_limit]]
            rcls = [f'row-{r.get("severity")}' if r.get("severity") in ("crit", "warn") else ""
                    for r in records[:tbl_limit]]
            tabs.append((cat, label, _table(["Fecha (UTC)", "Tipo", "Detalle", "Contexto"],
                                            rows, cat, rcls)))
    tabs.append(("custodia", "Cadena de custodia", coc_tbl))

    cards = "".join(
        f'<div class="card"><div class="num">{n}</div><div class="lbl">{_esc(lbl)}</div></div>'
        for lbl, n in card_items)
    errors_html = ""
    if parsed.get("_errors"):
        items = "".join(f"<li>{_esc(e['parser'])}: {_esc(e['error'])}</li>"
                        for e in parsed["_errors"])
        errors_html = (f'<div class="note"><strong>Avisos de parseo:</strong>'
                       f'<ul class="plain">{items}</ul></div>')

    nav = "".join(
        f'<button class="tab{" active" if i == 0 else ""}" '
        f'onclick="showTab(\'{tid}\',this)">{_esc(lbl)}</button>'
        for i, (tid, lbl, _) in enumerate(tabs))
    panels = "".join(
        f'<section id="tab-{tid}" class="panel{" active" if i == 0 else ""}">'
        f'<h2>{_esc(lbl)}</h2>{content}</section>'
        for i, (tid, lbl, content) in enumerate(tabs))

    doc = _HTML_TEMPLATE.format(
        title=_esc(case.get("name", "Triage forense")),
        case=_esc(case.get("name", "—")),
        examiner=_esc(case.get("examiner", "—")),
        generated=_fmt_ts(utils.now_utc()),
        hostname=_esc(host["hostname"]), os=_esc(host["os"]),
        integrity=f"{verified}/{len(manifest)}",
        tl_total=len(timeline), tl_shown=min(len(timeline), tl_limit),
        findings=findings_html, cards=cards, errors=errors_html,
        nav=nav, panels=panels, css=_CSS, js=_JS)

    path = out_dir / "report.html"
    path.write_text(doc, encoding="utf-8")
    log.info("Escrito report.html")
    return path


_CSS = """
:root{
  --bg:#0E1116; --panel:#161B22; --panel2:#1B222C; --line:#232A34;
  --ink:#E6EDF3; --muted:#8B97A5; --amber:#E0A34A; --blue:#6EA8FE;
  --red:#F0616D; --mono:ui-monospace,"SF Mono",SFMono-Regular,Consolas,monospace;
  --sans:system-ui,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font-family:var(--sans);
  font-size:14px;line-height:1.5}
.mono{font-family:var(--mono);font-size:12.5px}
.muted{color:var(--muted)}
.nowrap{white-space:nowrap}
.wrap{word-break:break-all}
header{border-bottom:1px solid var(--line);padding:22px 28px;
  background:linear-gradient(180deg,#12171F,#0E1116)}
.brand{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap}
.brand h1{font-size:20px;margin:0;letter-spacing:.02em}
.brand .badge{font-family:var(--mono);font-size:11px;color:var(--amber);
  border:1px solid var(--amber);border-radius:3px;padding:2px 8px}
.meta{display:flex;gap:26px;flex-wrap:wrap;margin-top:12px;color:var(--muted);
  font-size:12.5px}
.meta b{color:var(--ink);font-weight:600}
.meta .mono{color:var(--ink)}
.layout{padding:24px 28px;max-width:1500px}
.top{display:grid;grid-template-columns:1.3fr 1fr;gap:20px;margin-bottom:22px}
@media(max-width:900px){.top{grid-template-columns:1fr}}
.block{background:var(--panel);border:1px solid var(--line);border-radius:8px;
  padding:16px 18px}
.block h3{margin:0 0 12px;font-size:12px;text-transform:uppercase;
  letter-spacing:.08em;color:var(--muted)}
.cards{display:flex;gap:10px;flex-wrap:wrap}
.card{flex:1;min-width:84px;background:var(--panel2);border:1px solid var(--line);
  border-radius:6px;padding:12px 10px;text-align:center}
.card .num{font-family:var(--mono);font-size:24px;color:var(--amber);font-weight:600}
.card .lbl{font-size:11px;color:var(--muted);margin-top:2px}
ul.findings{list-style:none;margin:0;padding:0}
ul.findings li{padding:7px 10px 7px 26px;border-radius:5px;margin-bottom:6px;
  position:relative;background:var(--panel2);font-size:13px}
ul.findings li:before{position:absolute;left:9px;top:7px;font-family:var(--mono)}
.f-crit{border-left:3px solid var(--red)} .f-crit:before{content:"!";color:var(--red)}
.f-warn{border-left:3px solid var(--amber)} .f-warn:before{content:"▲";color:var(--amber);font-size:10px}
.f-info{border-left:3px solid var(--blue)} .f-info:before{content:"i";color:var(--blue)}
nav.tabs{display:flex;gap:4px;flex-wrap:wrap;border-bottom:1px solid var(--line);
  margin-bottom:0}
.tab{background:none;border:none;color:var(--muted);padding:10px 16px;cursor:pointer;
  font-family:var(--sans);font-size:13px;border-bottom:2px solid transparent}
.tab:hover{color:var(--ink)}
.tab.active{color:var(--amber);border-bottom-color:var(--amber)}
.panel{display:none;padding-top:18px}
.panel.active{display:block}
.panel h2{font-size:16px;margin:0 0 4px}
.tablewrap{margin-top:10px}
.filter{width:100%;max-width:320px;background:var(--panel2);border:1px solid var(--line);
  color:var(--ink);border-radius:5px;padding:7px 10px;margin-bottom:10px;
  font-family:var(--mono);font-size:12.5px}
.scroll{overflow:auto;border:1px solid var(--line);border-radius:8px;max-height:70vh}
table{border-collapse:collapse;width:100%;font-size:12.5px}
thead th{position:sticky;top:0;background:#11161D;text-align:left;padding:9px 12px;
  color:var(--muted);font-weight:600;white-space:nowrap;cursor:pointer;
  border-bottom:1px solid var(--line);user-select:none}
thead th:hover{color:var(--ink)}
.ar{margin-left:5px;opacity:.5;font-size:10px}
tbody td{padding:8px 12px;border-bottom:1px solid var(--line);vertical-align:top}
tbody tr:hover{background:var(--panel2)}
.row-crit{background:rgba(240,97,109,.07)}
.row-crit td:first-child{box-shadow:inset 3px 0 var(--red)}
.row-warn td:first-child{box-shadow:inset 3px 0 var(--amber)}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:8px;
  vertical-align:middle}
.src{font-weight:600}
.sev{font-family:var(--mono);font-size:10.5px;text-transform:uppercase;
  letter-spacing:.05em;padding:2px 6px;border-radius:3px;white-space:nowrap}
.sev-crit{color:var(--red);border:1px solid rgba(240,97,109,.5)}
.sev-warn{color:var(--amber);border:1px solid rgba(224,163,74,.5)}
.sev-info{color:var(--muted);border:1px solid var(--line)}
.hash{cursor:help}
.note{background:var(--panel2);border:1px solid var(--line);border-left:3px solid var(--amber);
  border-radius:6px;padding:12px 16px;margin-top:16px;font-size:13px}
ul.plain{margin:6px 0 0;padding-left:18px;color:var(--muted);font-family:var(--mono);font-size:12px}
footer{color:var(--muted);font-size:12px;padding:20px 28px;border-top:1px solid var(--line);
  margin-top:20px}
"""

_JS = """
function showTab(id,btn){
  document.querySelectorAll('.panel').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  document.getElementById('tab-'+id).classList.add('active');
  btn.classList.add('active');
}
function filterTable(id,q){
  q=q.toLowerCase();
  document.querySelectorAll('#'+id+' tbody tr').forEach(tr=>{
    tr.style.display = tr.textContent.toLowerCase().includes(q)?'':'none';
  });
}
function sortTable(id,col){
  var tb=document.querySelector('#'+id+' tbody');
  var rows=Array.from(tb.rows);
  var t=document.getElementById(id);
  var asc=t.getAttribute('data-sc')==String(col)?t.getAttribute('data-sa')!=='1':true;
  rows.sort(function(a,b){
    var x=a.cells[col].textContent.trim(), y=b.cells[col].textContent.trim();
    var nx=parseFloat(x.replace(/[^\\d.-]/g,'')), ny=parseFloat(y.replace(/[^\\d.-]/g,''));
    var both=!isNaN(nx)&&!isNaN(ny)&&x.replace(/[\\d.,:\\s-]/g,'')==='';
    var r = both ? nx-ny : x.localeCompare(y);
    return asc?r:-r;
  });
  rows.forEach(function(r){tb.appendChild(r)});
  t.setAttribute('data-sc',col); t.setAttribute('data-sa',asc?'1':'0');
  t.querySelectorAll('.ar').forEach(function(a){a.textContent=''});
  t.querySelectorAll('thead th')[col].querySelector('.ar').textContent=asc?'▲':'▼';
}
"""

_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title} · Triage forense</title>
<style>{css}</style></head>
<body>
<header>
  <div class="brand">
    <h1>Informe de triage forense</h1>
    <span class="badge">DFIR · Windows</span>
  </div>
  <div class="meta">
    <span>Caso: <b>{case}</b></span>
    <span>Analista: <b>{examiner}</b></span>
    <span>Equipo: <span class="mono">{hostname}</span> · {os}</span>
    <span>Generado: <span class="mono">{generated} UTC</span></span>
    <span>Integridad: <b>{integrity}</b> artefactos con hash</span>
  </div>
</header>
<div class="layout">
  <div class="top">
    <div class="block">
      <h3>Hallazgos automáticos</h3>
      <ul class="findings">{findings}</ul>
    </div>
    <div class="block">
      <h3>Artefactos parseados</h3>
      <div class="cards">{cards}</div>
      {errors}
    </div>
  </div>
  <nav class="tabs">{nav}</nav>
  {panels}
</div>
<footer>
  Generado por <b>ftriage</b> · super-timeline: {tl_shown} de {tl_total} observaciones ·
  Los datos crudos y completos están en <span class="mono">report.json</span> y
  <span class="mono">timeline.ndjson</span>. Uso exclusivamente para respuesta a incidentes.
</footer>
<script>{js}</script>
</body></html>"""


def write_reports(out_dir: Path, case: dict, manifest: list[dict],
                  parsed: dict, findings: list[dict] | None = None,
                  iocs: list[dict] | None = None) -> dict:
    """Construye timeline + hallazgos y emite los tres informes.

    `findings` lo aporta cada plataforma (Linux/macOS calculan los suyos); si es
    None se usan los hallazgos por defecto basados en eventos de Windows.
    """
    timeline = build_timeline(parsed)
    if findings is None:
        findings = build_findings(parsed, manifest)
    from . import assess as _assess
    assessment = _assess.assess(parsed, findings, manifest)
    json_path = write_json(out_dir, case, manifest, parsed, timeline, findings, assessment, iocs)
    html_path = write_html(out_dir, case, manifest, parsed, timeline, findings)
    return {"json": json_path, "html": html_path, "assessment": assessment,
            "ndjson": out_dir / "timeline.ndjson",
            "timeline_events": len(timeline), "findings": findings}
