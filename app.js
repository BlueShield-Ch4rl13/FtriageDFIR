// Los casos de ejemplo van en index.html como bloque de datos (no ejecutable)
const DEMO_CASES = JSON.parse(document.getElementById("casos-demo").textContent);

const SRC_COLOR = {"Evento":"#6EA8FE","Prefetch":"#E0A34A","Amcache":"#A6E22E","Shimcache":"#C77DFF",
  "Navegador":"#4DD0C4","Accesos":"#6EA8FE","Logs":"#E0A34A","Journal":"#4DD0C4","Shell":"#A6E22E",
  "Persistencia":"#F0616D","Cuentas":"#C77DFF","Cuarentena":"#F0616D","Unified Log":"#4DD0C4"};
const CAT_LABEL = {"eventlogs":"Eventos","prefetch":"Prefetch","amcache":"Amcache","shimcache":"Shimcache",
  "browsers":"Navegador","logins":"Accesos","logs":"Logs","journal":"Journal","shell":"Shell",
  "persistence":"Persistencia","accounts":"Cuentas","quarantine":"Cuarentena","unified_log":"Unified Log"};

function esc(s){return (s==null?"":String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));}
function fmtTs(t){return t?esc(t.replace("T"," ").replace("Z","")):"&mdash;";}
function sevClass(s){return s==="crit"?"row-crit":s==="warn"?"row-warn":"";}
// La severidad viene del report.json: solo valen las tres conocidas (un valor libre seria HTML del informe)
function sevBadge(s){const L={crit:"cr&iacute;tico",warn:"atenci&oacute;n",info:"info"};if(!Object.prototype.hasOwnProperty.call(L,s))s="info";return `<span class="sev sev-${s}">${L[s]}</span>`;}
function sevNodo(s){const L={crit:"cr\u00edtico",warn:"atenci\u00f3n",info:"info"};if(!Object.prototype.hasOwnProperty.call(L,s))s="info";
  const sp=document.createElement("span");sp.className="sev sev-"+s;sp.textContent=L[s];return sp;}
function h(html){const d=document.createElement("div");d.innerHTML=html;return d.firstElementChild;}
function safeColor(c){return (typeof c==="string"&&/^#[0-9a-fA-F]{3,8}$/.test(c))?c:"#8B97A5";}
function safeAttack(a){return (typeof a==="string"&&/^T\d{4}(\.\d{3})?$/.test(a))?a:"";}
function num(n){n=Number(n);return isFinite(n)?Math.max(0,Math.min(100,n)):0;}
// entero no acotado para contadores: coerciona y nunca deja pasar HTML
function ent(n){n=Number(n);return Number.isFinite(n)?Math.trunc(n):0;}

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
        <div><div class="k">Analista</div><div class="v">${((rep.case||{}).examiner?esc(rep.case.examiner):"&mdash;")}</div></div>
        <div><div class="k">Generado</div><div class="v">${fmtTs(rep.generated_utc)}</div></div>
        <div><div class="k">Integridad</div><div class="v">${integ.artifacts_verified!==undefined ? ent(integ.artifacts_verified)+'/'+ent(integ.artifacts_copied)+' idénticas al original' : ent(integ.artifacts_hashed)+'/'+ent(integ.artifacts_total)+' con hash (sin comparar con el original)'}</div></div>
        <div><div class="k">Confianza (${esc(a.confidence_tier||"?")})</div><div class="conf-bar"><span style="width:${num(a.confidence)}%"></span></div></div>
      </div>
    </div></div>`;
}
function reasonsHTML(a){
  const rs=(a.reasons||[]);
  const body = rs.length ? rs.map(r=>`<div class="reason"><span class="att">${esc(r.attack)}</span>
     <span class="txt">${esc(r.label)} <span class="muted">&times;${ent(r.count)}</span></span>
     <span class="pts">+${ent(r.points)}</span></div>`).join("")
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
  // Hasta 2000 filas con datos del report.json: con nodos y textContent, sin
  // pasar por HTML (lo que mas texto libre del equipo examinado lleva).
  const tbody=document.querySelector("#art-tbl tbody");
  tbody.textContent="";
  const filas=document.createDocumentFragment();
  for(const r of recs.slice(0,2000)){
    const v=val(r), tr=document.createElement("tr"), cls=sevClass(v.sev);
    if(cls) tr.className=cls;
    const celda=(texto,clase)=>{const td=document.createElement("td");td.className=clase;td.textContent=texto==null?"":String(texto);tr.appendChild(td);return td;};
    celda(v.ts?String(v.ts).replace("T"," ").replace("Z",""):"\u2014","m").style.whiteSpace="nowrap";
    celda(v.kind,"m");celda(v.sum,"m wrap");celda(v.det,"wrap");
    const td=document.createElement("td");td.appendChild(sevNodo(v.sev));tr.appendChild(td);
    filas.appendChild(tr);
  }
  tbody.appendChild(filas);
}

/* ---- IOCs ---- */
function buildIocs(iocs){
  const ext=iocs.filter(i=>!i.private).length;
  const rows=iocs.map(i=>`<tr><td class="m">${esc(i.type)}</td><td class="m wrap">${esc(i.defanged||i.value)}</td>
     <td class="m">${ent(i.count)||1}</td><td>${i.private?'<span class="badge">interno</span>':'<span class="badge ext">externo</span>'}</td>
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
      <td class="m">${m.method?esc(m.method):"&mdash;"}</td><td>${md5}</td><td>${sha}</td>
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

// Botones: sin onclick= en el HTML, para que la CSP no necesite 'unsafe-inline'
document.getElementById("btn-back").addEventListener("click", backToLanding);
document.getElementById("btn-json").addEventListener("click", exportJSON);
document.getElementById("btn-pdf").addEventListener("click", () => window.print());
document.getElementById("btn-cargar").addEventListener("click", () => document.getElementById("fi").click());
document.getElementById("drop").addEventListener("click", () => document.getElementById("fi").click());
document.querySelectorAll("[data-ejemplo]").forEach(b => b.addEventListener("click", () => loadExample(b.dataset.ejemplo)));
