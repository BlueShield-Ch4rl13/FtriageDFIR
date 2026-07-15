"""Compromise assessment: ¿está el equipo comprometido?

No existe un veredicto infalible. Lo que hace este módulo es lo que haría un
analista: ponderar los indicadores presentes, mapearlos a MITRE ATT&CK y emitir
un nivel de riesgo con una confianza en función de cuántos datos había para
juzgar. La salida es deliberadamente explicable: cada punto del riesgo viene de
una razón concreta que se puede auditar.

El resultado se incrusta en report.json (clave "assessment"), lo imprime la CLI
y lo muestra el dashboard.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable

# --- Utilidades de detección sobre los datos parseados ---
def _events(parsed):
    return parsed.get("eventlogs", []) or []


def _eid(parsed, *ids):
    ids = set(ids)
    return sum(1 for e in _events(parsed) if e.get("event_id") in ids)


def _cat(parsed, name):
    return parsed.get(name, []) or []


def _sev(records, level):
    return sum(1 for r in records if r.get("severity") == level)


def _text_hits(parsed, pattern):
    """Cuenta registros cuyo texto (summary/detail/details) casa con el patrón."""
    rx = re.compile(pattern, re.IGNORECASE)
    n = 0
    for cat, recs in parsed.items():
        if not isinstance(recs, list):
            continue
        for r in recs:
            blob = " ".join(str(v) for v in (
                r.get("summary", ""), r.get("detail", ""),
                " ".join(f"{k}={v}" for k, v in (r.get("details") or {}).items())))
            if rx.search(blob):
                n += 1
    return n


@dataclass
class Signal:
    id: str
    label: str            # texto legible del hallazgo
    tactic: str           # táctica MITRE
    attack: str           # técnica MITRE (T####)
    points_each: int      # puntos por ocurrencia
    points_cap: int       # tope de puntos de esta señal
    detector: Callable    # (parsed) -> nº de ocurrencias


# Reglas de evaluación. Cada una suma riesgo y, si dispara, aporta una técnica ATT&CK.
SIGNALS: list[Signal] = [
    # --- Anti-forense (señal fortísima de compromiso) ---
    Signal("log_cleared", "Borrado de registros de eventos", "Defense Evasion",
           "T1070.001", 35, 35, lambda p: _eid(p, "1102", "104")),
    # --- Credential access ---
    Signal("cred_dump", "Volcado de credenciales (mimikatz/LSASS)", "Credential Access",
           "T1003", 30, 30, lambda p: _text_hits(p, r"mimikatz|sekurlsa|lsass|logonpasswords")),
    # --- Persistencia ---
    Signal("svc_install", "Servicio instalado (persistencia)", "Persistence",
           "T1543.003", 12, 24, lambda p: _eid(p, "7045")),
    Signal("launchd", "LaunchDaemon/Agent sospechoso (persistencia)", "Persistence",
           "T1543.001", 15, 30, lambda p: sum(
               1 for r in _cat(p, "persistence")
               if r.get("kind") == "launchd" and r.get("severity") == "crit")),
    Signal("ld_preload", "Secuestro del enlazador dinámico (ld.so.preload)", "Persistence",
           "T1574.006", 35, 35, lambda p: max(
               sum(1 for r in _cat(p, "persistence") if "preload" in str(r.get("kind", "")).lower()),
               _text_hits(p, r"ld\.so\.preload"))),
    Signal("ssh_key", "Clave SSH añadida (authorized_keys)", "Persistence",
           "T1098.004", 15, 15, lambda p: _text_hits(p, r"authorized_keys")),
    Signal("scheduled", "Tarea/cron programada", "Persistence",
           "T1053", 6, 18, lambda p: _eid(p, "106", "140") + sum(
               1 for r in _cat(p, "persistence") if r.get("kind") == "cron")),
    # --- Cuentas ---
    Signal("new_account", "Cuenta de usuario creada", "Persistence",
           "T1136", 15, 30, lambda p: _eid(p, "4720") + sum(
               1 for r in _cat(p, "accounts") if "uid 0" in r.get("summary", "").lower())),
    # --- Ejecución ---
    Signal("powershell", "PowerShell ofuscado/descarga", "Execution",
           "T1059.001", 8, 24, lambda p: _eid(p, "4104")),
    Signal("shell_susp", "Comando de shell sospechoso (curl|bash, etc.)", "Execution",
           "T1059.004", 8, 24, lambda p: _sev(_cat(p, "shell"), "warn")),
    # --- Acceso inicial / movimiento lateral ---
    Signal("brute", "Fuerza bruta / accesos fallidos", "Credential Access",
           "T1110", 3, 20, lambda p: _eid(p, "4625") + _sev(_cat(p, "logins"), "warn")),
    Signal("rdp", "Acceso remoto RDP", "Lateral Movement",
           "T1021.001", 5, 15, lambda p: _eid(p, "21", "25", "1149")),
    # --- Descarga de herramientas ---
    Signal("ingress", "Descarga de herramienta/ejecutable", "Command and Control",
           "T1105", 8, 16, lambda p: len(_cat(p, "quarantine")) + sum(
               1 for r in _cat(p, "browsers") if r.get("kind") == "descarga")),
    Signal("c2_net", "Conexión de red saliente sospechosa (C2)", "Command and Control",
           "T1071", 8, 16, lambda p: _eid(p, "3")),
    # --- Malware confirmado por AV ---
    Signal("av_detect", "Detección de antivirus (Defender)", "Execution",
           "T1204", 20, 40, lambda p: _eid(p, "1116", "1117")),
]

# Bandas de veredicto (honestas: nivel de riesgo, no certeza absoluta)
BANDS = [
    (0, 15, "sin_indicios", "Sin indicios de compromiso", "#4FD6C4"),
    (16, 40, "sospechoso", "Actividad sospechosa", "#E0A34A"),
    (41, 70, "probable", "Probable compromiso", "#FF9F45"),
    (71, 100, "critico", "Compromiso muy probable", "#F0616D"),
]


def _band(score: int):
    for lo, hi, key, label, color in BANDS:
        if lo <= score <= hi:
            return key, label, color
    return "critico", "Compromiso muy probable", "#F0616D"


def _confidence(parsed) -> tuple[int, str]:
    """Confianza del veredicto según la cobertura de datos disponible."""
    cats = [c for c in parsed if isinstance(parsed[c], list) and c != "_errors"]
    with_data = sum(1 for c in cats if parsed[c])
    total_records = sum(len(parsed[c]) for c in cats)
    errors = len(parsed.get("_errors", []))
    score = min(100, with_data * 18 + min(40, total_records // 5) - errors * 5)
    score = max(10, score)
    tier = "alta" if score >= 70 else "media" if score >= 40 else "baja"
    return score, tier


def assess(parsed: dict, findings: list[dict], manifest: list[dict]) -> dict:
    """Devuelve el veredicto completo: riesgo, banda, confianza, razones y ATT&CK."""
    risk = 0
    reasons: list[dict] = []
    techniques: dict[str, dict] = {}
    for sig in SIGNALS:
        count = sig.detector(parsed)
        if not count:
            continue
        pts = min(sig.points_cap, count * sig.points_each)
        risk += pts
        reasons.append({"label": sig.label, "count": count, "points": pts,
                        "tactic": sig.tactic, "attack": sig.attack})
        techniques[sig.attack] = {"attack": sig.attack, "tactic": sig.tactic,
                                  "label": sig.label, "count": count}

    # Fallos de adquisición restan confianza pero también son señal de anti-forense leve
    risk = min(100, risk)
    reasons.sort(key=lambda r: r["points"], reverse=True)
    key, label, color = _band(risk)
    conf_score, conf_tier = _confidence(parsed)

    # Tácticas ordenadas por el orden de la kill chain
    tactic_order = ["Initial Access", "Execution", "Persistence", "Privilege Escalation",
                    "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
                    "Collection", "Command and Control", "Exfiltration", "Impact"]
    tech_list = sorted(techniques.values(),
                       key=lambda t: (tactic_order.index(t["tactic"]) if t["tactic"] in tactic_order else 99,
                                      t["attack"]))

    verdict_text = {
        "sin_indicios": "No se han encontrado indicadores de compromiso en los artefactos analizados. Ausencia de evidencia no es evidencia de ausencia: revisa también la timeline.",
        "sospechoso": "Se han detectado indicadores que merecen investigación, pero no concluyentes por sí solos.",
        "probable": "Varios indicadores apuntan a actividad maliciosa. Trata el equipo como probablemente comprometido y aísla si procede.",
        "critico": "Múltiples indicadores de alta confianza (p. ej. anti-forense, persistencia, credential access). Trata el equipo como comprometido: aíslalo y escala.",
    }[key]

    return {
        "risk_score": risk,
        "verdict_key": key,
        "verdict": label,
        "verdict_color": color,
        "verdict_text": verdict_text,
        "confidence": conf_score,
        "confidence_tier": conf_tier,
        "reasons": reasons,
        "attack_techniques": tech_list,
        "signals_triggered": len(reasons),
    }
