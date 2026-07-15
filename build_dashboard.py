#!/usr/bin/env python3
"""Genera el index.html autocontenido del dashboard DFIR e inyecta un caso demo."""
import json, sys
from pathlib import Path

TEMPLATE = r"""<!DOCTYPE html>
<html lang="es"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>DFIR · carlosvillalbalagos.com</title>
<style>
:root{
  --bg:#0A0E13; --panel:#12171F; --panel2:#171E28; --line:#232C38;
  --ink:#E6EDF3; --muted:#8B97A5; --teal:#4FD6C4; --amber:#E0A34A;
  --orange:#FF9F45; --red:#F0616D; --green:#4FD6C4;
  --mono:ui-monospace,"SF Mono",SFMono-Regular,Consolas,monospace;
  --sans:system-ui,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font-family:var(--sans);font-size:14px;line-height:1.5}
.mono{font-family:var(--mono)}
.muted{color:var(--muted)}
.wrap{word-break:break-all}
a{color:var(--teal);text-decoration:none}
a:hover{text-decoration:underline}
header{display:flex;align-items:center;gap:16px;flex-wrap:wrap;padding:16px 26px;
  border-bottom:1px solid var(--line);background:linear-gradient(180deg,#0E141C,#0A0E13);position:sticky;top:0;z-index:10}
.brand{display:flex;align-items:baseline;gap:10px}
.brand .logo{color:var(--teal);font-family:var(--mono);font-size:20px;font-weight:700;letter-spacing:.04em}
.brand .sub{color:var(--muted);font-family:var(--mono);font-size:12px}
.tlp{font-family:var(--mono);font-size:11px;color:var(--teal);border:1px solid var(--teal);border-radius:3px;padding:2px 7px}
header .sp{flex:1}
.btn{font-family:var(--sans);font-size:13px;background:var(--panel2);color:var(--ink);border:1px solid var(--line);
  border-radius:6px;padding:8px 14px;cursor:pointer}
.btn:hover{border-color:var(--teal);color:var(--teal)}
.btn.primary{background:var(--teal);color:#05221F;border-color:var(--teal);font-weight:600}
main{max-width:1500px;margin:0 auto;padding:24px 26px}

/* Landing */
#landing{text-align:center;padding:40px 0}
#landing h1{font-size:26px;margin:0 0 8px}
#landing p.lead{color:var(--muted);max-width:720px;margin:0 auto 8px}
.drop{margin:28px auto;max-width:640px;border:1.5px dashed var(--line);border-radius:12px;padding:44px 24px;
  background:var(--panel);cursor:pointer;transition:.15s}
.drop:hover,.drop.over{border-color:var(--teal);background:var(--panel2)}
.drop .big{font-family:var(--mono);color:var(--teal);font-size:15px}
.explain{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;max-width:900px;margin:26px auto 0;text-align:left}
.examples{display:flex;gap:10px;flex-wrap:wrap;align-items:center;justify-content:center;margin:22px auto 0;max-width:900px}
.examples .ex-label{color:var(--muted);font-size:13px;margin-right:4px}
.btn.ex .logo{color:var(--teal)}
.explain .step{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:14px 16px}
.explain .step b{color:var(--teal);font-family:var(--mono);font-size:12px}
.note{background:var(--panel);border:1px solid var(--line);border-left:3px solid var(--amber);border-radius:6px;
  padding:12px 16px;max-width:900px;margin:22px auto 0;text-align:left;font-size:13px;color:var(--muted)}

/* Verdict hero */
.hero{display:grid;grid-template-columns:220px 1fr;gap:22px;background:var(--panel);border:1px solid var(--line);
  border-radius:12px;padding:22px;margin-bottom:18px}
@media(max-width:760px){.hero{grid-template-columns:1fr}}
.gauge{display:flex;flex-direction:column;align-items:center;justify-content:center}
.gauge .verdict{font-family:var(--mono);font-size:13px;text-align:center;margin-top:8px;font-weight:600}
.hero .right h2{margin:0 0 4px;font-size:19px}
.hero .cdesc{color:var(--ink);font-size:13.5px;margin:0 0 8px;opacity:.9}
.hero .vtext{color:var(--muted);font-size:13px;margin:6px 0 14px;max-width:720px}
.facts{display:flex;gap:26px;flex-wrap:wrap;font-size:12.5px}
.facts .k{color:var(--muted)} .facts .v{color:var(--ink);font-family:var(--mono)}
.conf-bar{height:6px;background:var(--panel2);border-radius:3px;overflow:hidden;width:180px;margin-top:4px}
.conf-bar span{display:block;height:100%;background:var(--teal)}

.grid2{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:18px}
@media(max-width:900px){.grid2{grid-template-columns:1fr}}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px 18px}
.card h3{margin:0 0 12px;font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted)}
.reason{display:flex;align-items:center;gap:10px;padding:7px 0;border-bottom:1px solid var(--line)}
.reason:last-child{border-bottom:none}
.reason .txt{flex:1}.reason .pts{font-family:var(--mono);font-size:12px;color:var(--amber)}
.reason .att{font-family:var(--mono);font-size:11px;color:var(--teal);border:1px solid var(--line);border-radius:3px;padding:1px 5px}
.tactic{margin-bottom:12px}
.tactic .tname{font-family:var(--mono);font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:5px}
.chip{display:inline-block;font-family:var(--mono);font-size:11.5px;color:var(--ink);background:var(--panel2);
  border:1px solid var(--line);border-radius:4px;padding:3px 8px;margin:0 5px 5px 0}
.chip b{color:var(--teal)}

/* Tabs & tables */
nav.tabs{display:flex;gap:4px;flex-wrap:wrap;border-bottom:1px solid var(--line);margin-bottom:4px}
.tab{background:none;border:none;color:var(--muted);padding:10px 16px;cursor:pointer;font-family:var(--sans);
  font-size:13px;border-bottom:2px solid transparent}
.tab:hover{color:var(--ink)}.tab.active{color:var(--teal);border-bottom-color:var(--teal)}
.panel{display:none;padding-top:16px}.panel.active{display:block}
.controls{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:10px}
.controls input,.controls select{background:var(--panel2);border:1px solid var(--line);color:var(--ink);
  border-radius:6px;padding:7px 10px;font-family:var(--mono);font-size:12.5px}
.controls input{flex:1;min-width:200px}
.subtabs{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:12px}
.subtab{font-family:var(--mono);font-size:12px;background:var(--panel2);border:1px solid var(--line);color:var(--muted);
  border-radius:5px;padding:5px 11px;cursor:pointer}
.subtab.active{color:var(--teal);border-color:var(--teal)}
.scroll{overflow:auto;border:1px solid var(--line);border-radius:8px;max-height:66vh}
table{border-collapse:collapse;width:100%;font-size:12.5px}
thead th{position:sticky;top:0;background:#0F151D;text-align:left;padding:9px 12px;color:var(--muted);font-weight:600;
  white-space:nowrap;border-bottom:1px solid var(--line)}
tbody td{padding:8px 12px;border-bottom:1px solid var(--line);vertical-align:top}
tbody tr:hover{background:var(--panel2)}
td.m,.m{font-family:var(--mono);font-size:12px}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:8px;vertical-align:middle}
.row-crit{background:rgba(240,97,109,.08)} .row-crit td:first-child{box-shadow:inset 3px 0 var(--red)}
.row-warn{background:rgba(224,163,74,.06)} .row-warn td:first-child{box-shadow:inset 3px 0 var(--amber)}
.sev{font-family:var(--mono);font-size:10.5px;text-transform:uppercase;padding:2px 6px;border-radius:3px}
.sev-crit{color:var(--red);border:1px solid rgba(240,97,109,.5)}
.sev-warn{color:var(--amber);border:1px solid rgba(224,163,74,.5)}
.sev-info{color:var(--muted);border:1px solid var(--line)}
.badge{font-family:var(--mono);font-size:11px;padding:2px 7px;border-radius:3px;border:1px solid var(--line);color:var(--muted)}
.badge.ext{color:var(--red);border-color:rgba(240,97,109,.5)}
.hash{cursor:help}
footer{color:var(--muted);font-size:12px;padding:20px 26px;border-top:1px solid var(--line);margin-top:24px;text-align:center}
@media print{
  header,.controls,.subtabs,nav.tabs,.drop,.btn{display:none!important}
  .panel{display:block!important;page-break-inside:avoid}
  .scroll{max-height:none!important;overflow:visible!important}
  body{background:#fff;color:#000}.card,.hero{border-color:#ccc}
}
.hidden{display:none}
</style></head>
<body>
<header>
  <div class="brand"><span class="logo">&#9679; DFIR</span><span class="sub">carlosvillalbalagos.com</span></div>
  <span class="tlp">TLP:CLEAR</span>
  <span class="sp"></span>
  <button class="btn hidden" id="btn-back" onclick="backToLanding()">&larr; Nuevo an&aacute;lisis</button>
  <button class="btn hidden" id="btn-json" onclick="exportJSON()">Descargar JSON</button>
  <button class="btn hidden" id="btn-pdf" onclick="window.print()">Guardar PDF</button>
  <button class="btn primary" onclick="document.getElementById('fi').click()">Cargar report.json</button>
</header>
<main>
  <section id="landing">
    <h1>An&aacute;lisis forense y evaluaci&oacute;n de compromiso</h1>
    <p class="lead">Sube el <span class="mono">report.json</span> generado por el agente <b>ftriage</b> en el equipo
    analizado (Windows, Linux o macOS) y obt&eacute;n el veredicto de compromiso, el mapeo a MITRE ATT&amp;CK,
    la timeline unificada y todos los artefactos.</p>
    <div class="drop" id="drop" onclick="document.getElementById('fi').click()">
      <div class="big">Arrastra aqu&iacute; un report.json &mdash; o pulsa para elegirlo</div>
      <div class="muted" style="margin-top:8px">Todo el an&aacute;lisis ocurre en tu navegador. Ning&uacute;n dato se sube a ning&uacute;n servidor.</div>
    </div>
    <div class="examples">
      <span class="ex-label">O explora un caso de ejemplo:</span>
      <button class="btn ex" onclick="loadExample('windows')">&#9679; Windows &mdash; intrusi&oacute;n</button>
      <button class="btn ex" onclick="loadExample('linux')">&#9679; Linux &mdash; rootkit</button>
      <button class="btn ex" onclick="loadExample('macos')">&#9679; macOS &mdash; persistencia</button>
    </div>
    <div class="explain">
      <div class="step"><b>1 &middot; Recolectar</b><div>Ejecuta <span class="mono">ftriage triage</span> en el equipo (como admin/root). Recolecta artefactos a nivel de sistema y calcula hashes.</div></div>
      <div class="step"><b>2 &middot; Cargar</b><div>Sube aqu&iacute; el <span class="mono">report.json</span>. El dashboard lo interpreta al vuelo.</div></div>
      <div class="step"><b>3 &middot; Decidir</b><div>Veredicto de riesgo, ATT&amp;CK y evidencias para saber si aislar y escalar.</div></div>
    </div>
    <div class="note"><b>Privacidad:</b> no se guarda ning&uacute;n dato del usuario &mdash; ni en el servidor ni en el navegador (sin cookies ni almacenamiento local). El informe solo existe en memoria mientras lo analizas y desaparece al cerrar o recargar la p&aacute;gina. Lo que quieras conservar lo descargas a tu propio ordenador (JSON o PDF).<br><br><b>Nota honesta:</b> una web no puede leer el kernel de un equipo remoto (el navegador est&aacute; aislado); por eso el agente recolecta en el propio equipo y aqu&iacute; se analiza el resultado. Y ninguna herramienta da un veredicto infalible: esto es una <b>evaluaci&oacute;n de compromiso</b> ponderada, con un nivel de confianza seg&uacute;n los datos disponibles.</div>
  </section>
  <section id="case" class="hidden"></section>
</main>
<footer>DFIR &middot; carlosvillalbalagos.com &mdash; capa de an&aacute;lisis sobre el agente ftriage &middot; uso exclusivamente para respuesta a incidentes.</footer>
<input type="file" id="fi" accept=".json,application/json" class="hidden">
<script>
const DEMO_CASES = {"windows":__DEMO_WINDOWS__,"linux":__DEMO_LINUX__,"macos":__DEMO_MACOS__};

const SRC_COLOR = {"Evento":"#6EA8FE","Prefetch":"#E0A34A","Amcache":"#A6E22E","Shimcache":"#C77DFF",
  "Navegador":"#4DD0C4","Accesos":"#6EA8FE","Logs":"#E0A34A","Journal":"#4DD0C4","Shell":"#A6E22E",
  "Persistencia":"#F0616D","Cuentas":"#C77DFF","Cuarentena":"#F0616D","Unified Log":"#4DD0C4"};
const CAT_LABEL = {"eventlogs":"Eventos","prefetch":"Prefetch","amcache":"Amcache","shimcache":"Shimcache",
  "browsers":"Navegador","logins":"Accesos","logs":"Logs","journal":"Journal","shell":"Shell",
  "persistence":"Persistencia","accounts":"Cuentas","quarantine":"Cuarentena","unified_log":"Unified Log"};

function esc(s){return (s==null?"":String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));}
function fmtTs(t){return t?esc(t.replace("T"," ").replace("Z","")):"&mdash;";}
function sevClass(s){return s==="crit"?"row-crit":s==="warn"?"row-warn":"";}
function sevBadge(s){const l={crit:"cr&iacute;tico",warn:"atenci&oacute;n",info:"info"}[s]||s;return `<span class="sev sev-${s}">${l}</span>`;}
function h(html){const d=document.createElement("div");d.innerHTML=html;return d.firstElementChild;}
function safeColor(c){return (typeof c==="string"&&/^#[0-9a-fA-F]{3,8}$/.test(c))?c:"#8B97A5";}
function safeAttack(a){return (typeof a==="string"&&/^T\d{4}(\.\d{3})?$/.test(a))?a:"";}
function num(n){n=Number(n);return isFinite(n)?Math.max(0,Math.min(100,n)):0;}

let CURRENT=null;

function render(rep){
  CURRENT=rep;
  document.getElementById("landing").classList.add("hidden");
  ["btn-back","btn-json","btn-pdf"].forEach(id=>document.getElementById(id).classList.remove("hidden"));
  const c=document.getElementById("case");c.classList.remove("hidden");
  const a=rep.assessment||{}, host=rep.host||{}, integ=rep.integrity||{};
  c.innerHTML =
    heroHTML(rep,a,host,integ) +
    `<div class="grid2">${reasonsHTML(a)}${attackHTML(a)}</div>` +
    tabsHTML(rep);
  wireTabs();
  buildTimeline(rep.timeline||[]);
  buildArtifacts(rep.artifacts||{});
  buildIocs(rep.iocs||[]);
  buildCustody(rep.chain_of_custody||[]);
}

function gauge(score,color){
  score=num(score);color=safeColor(color);
  const r=64,c=2*Math.PI*r,off=c*(1-score/100);
  return `<svg width="150" height="150" viewBox="0 0 150 150">
    <circle cx="75" cy="75" r="${r}" fill="none" stroke="#171E28" stroke-width="13"/>
    <circle cx="75" cy="75" r="${r}" fill="none" stroke="${color}" stroke-width="13" stroke-linecap="round"
      stroke-dasharray="${c}" stroke-dashoffset="${off}" transform="rotate(-90 75 75)"/>
    <text x="75" y="70" text-anchor="middle" fill="${color}" font-family="var(--mono)" font-size="34" font-weight="700">${score}</text>
    <text x="75" y="92" text-anchor="middle" fill="#8B97A5" font-family="var(--mono)" font-size="12">/ 100 riesgo</text>
  </svg>`;
}
function heroHTML(rep,a,host,integ){
  const col=safeColor(a.verdict_color);
  return `<div class="hero">
    <div class="gauge">${gauge(a.risk_score||0,col)}<div class="verdict" style="color:${col}">${esc((a.verdict||"").toUpperCase())}</div></div>
    <div class="right">
      <h2>${esc((rep.case||{}).name||"Caso sin nombre")}</h2>
      ${(rep.case||{}).description?`<div class="cdesc">${esc(rep.case.description)}</div>`:""}
      <div class="vtext">${esc(a.verdict_text||"")}</div>
      <div class="facts">
        <div><div class="k">Equipo</div><div class="v">${esc(host.hostname||"?")} &middot; ${esc(host.os||"")}</div></div>
        <div><div class="k">Analista</div><div class="v">${esc((rep.case||{}).examiner||"&mdash;")}</div></div>
        <div><div class="k">Generado</div><div class="v">${fmtTs(rep.generated_utc)}</div></div>
        <div><div class="k">Integridad</div><div class="v">${integ.artifacts_hashed||0}/${integ.artifacts_total||0} con hash</div></div>
        <div><div class="k">Confianza (${esc(a.confidence_tier||"?")})</div><div class="conf-bar"><span style="width:${a.confidence||0}%"></span></div></div>
      </div>
    </div></div>`;
}
function reasonsHTML(a){
  const rs=(a.reasons||[]);
  const body = rs.length ? rs.map(r=>`<div class="reason"><span class="att">${esc(r.attack)}</span>
     <span class="txt">${esc(r.label)} <span class="muted">&times;${r.count}</span></span>
     <span class="pts">+${r.points}</span></div>`).join("")
    : `<div class="muted">Sin indicadores de riesgo detectados.</div>`;
  return `<div class="card"><h3>&iquest;Por qu&eacute;? &mdash; evidencias que suman al riesgo</h3>${body}</div>`;
}
function attackHTML(a){
  const t=(a.attack_techniques||[]);
  if(!t.length) return `<div class="card"><h3>MITRE ATT&amp;CK</h3><div class="muted">Sin t&eacute;cnicas mapeadas.</div></div>`;
  const byT={};t.forEach(x=>{(byT[x.tactic]=byT[x.tactic]||[]).push(x);});
  const order=["Initial Access","Execution","Persistence","Privilege Escalation","Defense Evasion",
    "Credential Access","Discovery","Lateral Movement","Collection","Command and Control","Exfiltration","Impact"];
  const tacts=Object.keys(byT).sort((x,y)=>order.indexOf(x)-order.indexOf(y));
  const body=tacts.map(tc=>`<div class="tactic"><div class="tname">${esc(tc)}</div>`+
    byT[tc].map(x=>{const id=safeAttack(x.attack);const inner=`<b>${esc(x.attack)}</b> ${esc(x.label)}`;
      return id?`<a class="chip" href="https://attack.mitre.org/techniques/${id.replace('.','/')}/" target="_blank" rel="noopener">${inner}</a>`:`<span class="chip">${inner}</span>`;}).join("")+`</div>`).join("");
  return `<div class="card"><h3>MITRE ATT&amp;CK &mdash; ${t.length} t&eacute;cnica(s)</h3>${body}</div>`;
}
function tabsHTML(rep){
  return `<nav class="tabs">
    <button class="tab active" data-t="tl">Timeline</button>
    <button class="tab" data-t="art">Artefactos</button>
    <button class="tab" data-t="ioc">IOCs</button>
    <button class="tab" data-t="coc">Cadena de custodia</button></nav>
    <section id="p-tl" class="panel active"><div class="controls">
      <input id="tl-q" placeholder="Filtrar la timeline&hellip;">
      <select id="tl-src"><option value="">Todas las fuentes</option></select>
      <select id="tl-sev"><option value="">Toda severidad</option><option value="crit">Cr&iacute;tico</option><option value="warn">Atenci&oacute;n</option><option value="info">Info</option></select>
    </div><div class="scroll"><table id="tl-tbl"><thead><tr><th>Fecha (UTC)</th><th>Fuente</th><th>Tipo</th><th>Detalle</th><th>Contexto</th></tr></thead><tbody></tbody></table></div></section>
    <section id="p-art" class="panel"><div class="subtabs" id="art-subtabs"></div><div class="scroll"><table id="art-tbl"><thead></thead><tbody></tbody></table></div></section>
    <section id="p-ioc" class="panel"></section>
    <section id="p-coc" class="panel"></section>`;
}
function wireTabs(){
  document.querySelectorAll(".tab").forEach(b=>b.onclick=()=>{
    document.querySelectorAll(".tab").forEach(x=>x.classList.remove("active"));
    document.querySelectorAll(".panel").forEach(x=>x.classList.remove("active"));
    b.classList.add("active");document.getElementById("p-"+b.dataset.t).classList.add("active");
  });
}

/* ---- Timeline ---- */
let TL=[];
function buildTimeline(tl){
  TL=tl;
  const srcs=[...new Set(tl.map(t=>t.source))].sort();
  const sel=document.getElementById("tl-src");
  srcs.forEach(s=>sel.appendChild(h(`<option value="${esc(s)}">${esc(s)}</option>`)));
  ["tl-q","tl-src","tl-sev"].forEach(id=>document.getElementById(id).addEventListener("input",drawTL));
  drawTL();
}
function drawTL(){
  const q=document.getElementById("tl-q").value.toLowerCase();
  const src=document.getElementById("tl-src").value, sev=document.getElementById("tl-sev").value;
  const rows=TL.filter(t=>(!src||t.source===src)&&(!sev||t.severity===sev)&&
    (!q||JSON.stringify(t).toLowerCase().includes(q))).slice(0,3000);
  const tb=document.querySelector("#tl-tbl tbody");
  tb.innerHTML=rows.map(t=>{const col=SRC_COLOR[t.source]||"#8B97A5";
    return `<tr class="${sevClass(t.severity)}"><td class="m" style="white-space:nowrap"><span class="dot" style="background:${col}"></span>${fmtTs(t.timestamp)}</td>
     <td style="color:${col};font-weight:600">${esc(t.source)}</td><td>${esc(t.type)}</td>
     <td class="m wrap">${esc(t.summary)}</td><td class="muted wrap">${esc(t.detail)}</td></tr>`;}).join("");
}

/* ---- Artefactos ---- */
let ARTS={},ARTKEYS=[];
function buildArtifacts(arts){
  ARTS=arts;ARTKEYS=Object.keys(arts).filter(k=>Array.isArray(arts[k])&&arts[k].length);
  const st=document.getElementById("art-subtabs");st.innerHTML="";
  ARTKEYS.forEach((k,i)=>{const b=h(`<button class="subtab${i===0?' active':''}">${esc(CAT_LABEL[k]||k)} (${arts[k].length})</button>`);
    b.onclick=()=>{document.querySelectorAll("#art-subtabs .subtab").forEach(x=>x.classList.remove("active"));b.classList.add("active");drawArt(k);};st.appendChild(b);});
  if(ARTKEYS.length) drawArt(ARTKEYS[0]); else document.getElementById("p-art").innerHTML='<div class="muted">Sin artefactos.</div>';
}
function drawArt(k){
  const recs=ARTS[k]||[];
  const cols=["Fecha (UTC)","Tipo","Resumen","Detalle","Sev."];
  document.querySelector("#art-tbl thead").innerHTML="<tr>"+cols.map(c=>`<th>${c}</th>`).join("")+"</tr>";
  const val=r=>({
    ts:r.timestamp||r.last_run||r.last_modified,
    kind:r.kind||("EID "+r.event_id)||"",
    sum:r.summary||r.description||r.path||r.url||r.executable||"",
    det:r.detail||r.title||r.channel||(r.details?Object.entries(r.details).map(([a,b])=>a+"="+b).join(" · "):"")||(r.sha1?("SHA1 "+r.sha1):"")||"",
    sev:r.severity||(["1102","104","1116","1117"].includes(r.event_id)?"crit":["4625","7045","4720","4104"].includes(r.event_id)?"warn":"info")
  });
  document.querySelector("#art-tbl tbody").innerHTML=recs.slice(0,2000).map(r=>{const v=val(r);
    return `<tr class="${sevClass(v.sev)}"><td class="m" style="white-space:nowrap">${fmtTs(v.ts)}</td>
     <td class="m">${esc(v.kind)}</td><td class="m wrap">${esc(v.sum)}</td><td class="wrap">${esc(v.det)}</td><td>${sevBadge(v.sev)}</td></tr>`;}).join("");
}

/* ---- IOCs ---- */
function buildIocs(iocs){
  const ext=iocs.filter(i=>!i.private).length;
  const rows=iocs.map(i=>`<tr><td class="m">${esc(i.type)}</td><td class="m wrap">${esc(i.defanged||i.value)}</td>
     <td class="m">${i.count||1}</td><td>${i.private?'<span class="badge">interno</span>':'<span class="badge ext">externo</span>'}</td>
     <td class="muted m">${esc((i.sources||[]).join(", "))}</td></tr>`).join("");
  document.getElementById("p-ioc").innerHTML=
    `<div class="muted" style="margin-bottom:10px">${iocs.length} indicador(es) &middot; ${ext} externo(s). Formato compatible con el pipeline de News CTI.</div>
     <div class="scroll"><table><thead><tr><th>Tipo</th><th>Valor (defang)</th><th>Veces</th><th>&Aacute;mbito</th><th>Artefactos</th></tr></thead><tbody>${rows||'<tr><td class="muted" colspan=5>Sin IOCs.</td></tr>'}</tbody></table></div>`;
}

/* ---- Cadena de custodia ---- */
function buildCustody(coc){
  const rows=coc.map(m=>{const ok=m.status==="ok";
    const md5=m.md5?`<span class="m hash" title="${esc(m.md5)}">${esc(m.md5.slice(0,12))}&hellip;</span>`:'<span class="muted">&mdash;</span>';
    const sha=m.sha256?`<span class="m hash" title="${esc(m.sha256)}">${esc(m.sha256.slice(0,16))}&hellip;</span>`:'<span class="muted">&mdash;</span>';
    return `<tr class="${ok?'':'row-crit'}"><td class="m">${esc(m.category)}</td><td class="m wrap">${esc(m.source)}</td>
      <td class="m">${esc(m.method||"&mdash;")}</td><td>${md5}</td><td>${sha}</td>
      <td><span class="sev sev-${ok?'info':'crit'}">${esc(m.status)}</span></td></tr>`;}).join("");
  document.getElementById("p-coc").innerHTML=
    `<div class="muted" style="margin-bottom:10px">Cada artefacto con su MD5 y SHA-256 &mdash; verificable con otras herramientas.</div>
     <div class="scroll"><table><thead><tr><th>Categor&iacute;a</th><th>Origen</th><th>M&eacute;todo</th><th>MD5</th><th>SHA-256</th><th>Estado</th></tr></thead><tbody>${rows}</tbody></table></div>`;
}

/* ---- Carga de ficheros ---- */
function loadExample(os){const c=DEMO_CASES[os];if(c)render(c);}
function backToLanding(){
  CURRENT=null;
  document.getElementById("case").classList.add("hidden");
  document.getElementById("landing").classList.remove("hidden");
  ["btn-back","btn-json","btn-pdf"].forEach(id=>document.getElementById(id).classList.add("hidden"));
  window.scrollTo(0,0);
}
function exportJSON(){
  if(!CURRENT)return;
  const name=((CURRENT.case||{}).name||"caso").replace(/[^\w.-]+/g,"_");
  const blob=new Blob([JSON.stringify(CURRENT,null,2)],{type:"application/json"});
  const a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download=name+".json";
  document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(a.href),1000);
}
function loadFile(file){
  if(file.size>50*1024*1024){alert("El fichero es demasiado grande (l\u00edmite 50 MB).");return;}
  const rd=new FileReader();
  rd.onload=e=>{
    let rep;
    try{rep=JSON.parse(e.target.result);}catch(err){alert("No es un JSON v\u00e1lido: "+err);return;}
    if(!rep||typeof rep!=="object"||Array.isArray(rep)||(!rep.artifacts&&!rep.timeline&&!rep.assessment)){
      alert("No parece un report.json de ftriage (faltan artifacts / timeline / assessment).");return;}
    render(rep);
  };
  rd.onerror=()=>alert("No se pudo leer el fichero.");
  rd.readAsText(file);
}
document.getElementById("fi").addEventListener("change",e=>{if(e.target.files[0])loadFile(e.target.files[0]);});
const drop=document.getElementById("drop");
["dragenter","dragover"].forEach(ev=>document.addEventListener(ev,e=>{e.preventDefault();if(drop)drop.classList.add("over");}));
["dragleave","drop"].forEach(ev=>document.addEventListener(ev,e=>{e.preventDefault();if(drop)drop.classList.remove("over");}));
document.addEventListener("drop",e=>{if(e.dataTransfer.files[0])loadFile(e.dataTransfer.files[0]);});
</script>
</body></html>"""

def _emb(p):
    d = json.loads(Path(p).read_text(encoding="utf-8"))
    return json.dumps(d, ensure_ascii=False).replace("</", "<\\/").replace("\u2028", " ").replace("\u2029", " ")

html = (TEMPLATE
        .replace("__DEMO_WINDOWS__", _emb(sys.argv[1]))
        .replace("__DEMO_LINUX__", _emb(sys.argv[2]))
        .replace("__DEMO_MACOS__", _emb(sys.argv[3])))
out = Path(sys.argv[4]); out.write_text(html, encoding="utf-8")
print(f"Dashboard escrito: {out} ({len(html)//1024} KB)")
