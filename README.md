# 🔍 ftriage — Plataforma de triage forense y adquisición (DFIR)

Recolector y analizador de artefactos forenses **multiplataforma** (Windows, Linux y macOS) para respuesta a incidentes, con **adquisición de imágenes de disco** para Autopsy/X-Ways/FTK. Para cada caso genera un **informe HTML navegable** con super-timeline unificada, salidas **JSON/NDJSON** para SIEM, **IOCs** extraídos automáticamente y una **cadena de custodia** con MD5 + SHA-256 por artefacto.

> ⚠️ **Uso exclusivamente defensivo** (respuesta a incidentes sobre sistemas propios o autorizados). TLP:CLEAR, IOCs defangueados.

## Capacidades

- **Triage multi-SO** con detección automática del anfitrión o `--target-os` (útil para analizar una imagen montada de otro SO).
- **Imaging forense** de discos/SSD (RAW y E01) con hashes y verificación bit a bit.
- **Super-timeline unificada**: fusiona todos los artefactos en un único eje temporal.
- **Hallazgos automáticos** por SO (anti-forense, persistencia, cuentas backdoor, malware…).
- **Extracción de IOCs** (IPs, dominios, URLs, hashes) en formato compatible con pipelines de CTI.
- **Cadena de custodia** con MD5 + SHA-256 y método de adquisición por fichero.
- **Tolerancia a fallos**: un artefacto ilegible se registra y el análisis continúa.

## Artefactos por sistema operativo

| Windows | Linux | macOS |
|---|---|---|
| Event logs (.evtx) | auth.log / secure / syslog | Unified log (`log show`) + system.log |
| Prefetch | journald (`journalctl`) | LaunchDaemons / LaunchAgents (persistencia) |
| Amcache (SHA-1) | wtmp / btmp (accesos y fallos) | Historial navegador (Safari/Chrome/Firefox) |
| Shimcache (AppCompatCache) | Historial de shell (bash/zsh) | Quarantine (descargas) |
| Historial navegador (Chrome/Edge/Firefox) | Persistencia (cron, systemd, authorized_keys, ld.so.preload) | Historial de shell (zsh/bash) |
| | Cuentas (/etc/passwd, sudoers) | Cuentas locales (dslocal) |
| | Historial navegador | cron |

## Estrategia de parseo (híbrida)

Copia cruda **siempre**; parseo con el mejor motor disponible. En Windows, event logs / amcache / shimcache / navegadores se parsean con librerías Python puras (`python-evtx`, `python-registry`, `sqlite3`); el prefetch usa **PECmd** (Eric Zimmerman) si está disponible. En Linux/macOS todo el parseo es nativo en Python (logs de texto, `journalctl`/`log` en JSON, formato binario `utmp`, `plistlib`, SQLite). Si un artefacto está ausente, bloqueado o corrupto, se registra el aviso y se continúa.

## Instalación

```bash
git clone https://github.com/BlueShield-Ch4rl13/ftriage
cd ftriage
pip install -r requirements.txt
```

Opcional: [EZ Tools](https://ericzimmerman.github.io/) (prefetch) y `libewf`/`ewfacquire` (imágenes E01).

## Uso — triage

```bash
# Detecta el SO del propio equipo (ejecutar como administrador/root)
python triage.py triage --case IR-2026-014 --examiner "C. Villalba"

# Forzar el SO objetivo (p. ej. imagen Windows montada, analizada desde Linux)
python triage.py triage --target-os windows --root /mnt/imagen --case IR-2026-014

# Triage de un equipo Linux o macOS
sudo python triage.py triage --target-os linux --case IR-2026-014
sudo python triage.py triage --target-os macos --case IR-2026-014

# Adquisición Windows con instantánea de volumen
python triage.py triage --vss --case IR-2026-014

# Reanalizar una carpeta ya recolectada, sin volver a copiar
python triage.py triage --parse-only ./triage_HOST_20260714
```

Flags útiles: `--artifacts` (subconjunto de categorías, dependen del SO), `--collect-only`, `--no-iocs`, `--ez-tools RUTA`, `-v`.

## Uso — imaging

```bash
# Imagen RAW de un disco, dividida en segmentos de 2 GB, con verificación
sudo python triage.py image --source /dev/sdb --output ./caso --case IR-2026-014 --split 2G

# Imagen E01 (requiere libewf/ewfacquire); si no está, cae a RAW
sudo python triage.py image --source /dev/sdb --output ./caso --format e01 --case IR-2026-014
```

La imagen se acompaña de un `.info.txt`/`.info.json` estilo dc3dd/Guymager con MD5+SHA256, tamaño, duración y **resultado de verificación** (relee la imagen y compara con el origen). Directamente cargable en Autopsy como "Disk Image". La fuente se abre en solo lectura; **en un caso real, usa siempre un write-blocker hardware**.

## Salida

```
triage_<host>_<fecha>/
├── report.html          # informe navegable (super-timeline, hallazgos, tablas por artefacto)
├── report.json          # informe estructurado completo
├── timeline.ndjson      # una observación por línea → SIEM (Splunk/Elastic/Sentinel)
├── iocs.json / iocs.csv # indicadores extraídos (defangueados) → compatible con News CTI
├── manifest.json        # cadena de custodia: MD5+SHA256, método y tamaño por fichero
├── triage.log
└── artifacts/           # copia cruda de todos los artefactos (evidencia)
```

- **Imagen de disco → Autopsy / X-Ways / FTK.** **Timeline NDJSON → SIEM.** Son destinos distintos y la herramienta produce ambos.

## Arquitectura

```
ftriage/
├── triage.py          # CLI (subcomandos triage / image)
├── platforms.py       # despachador por SO (auto-detección o --target-os)
├── windows_adapter.py / linux.py / macos.py   # recolección + parseo por SO
├── collectors.py + parsers.py                  # motor Windows
├── imaging.py         # adquisición de imágenes (RAW/E01, hashes, verificación)
├── iocs.py            # extracción de indicadores
├── reporting.py       # super-timeline + informes HTML/JSON/NDJSON (genérico multi-SO)
└── utils.py           # hashing, timestamps (7 epochs), copia, parsers compartidos
```

## Notas de diseño (para entrevista)

- **Una super-timeline por encima de todo.** Reunir cinco (o siete) artefactos en un solo eje es como empieza de verdad un análisis DFIR; ver "servicio instalado → accesos fallidos → log borrado" en una tabla vale más que cinco herramientas.
- **La copia cruda es la evidencia; el parseo, una conveniencia.** Todo se adquiere con hash antes de interpretarse, reproducible con otras herramientas.
- **Siete epochs normalizados a UTC**: FILETIME (1601), WebKit, PRTime, CFAbsoluteTime (2001), Unix, syslog y journald — para que la timeline sea coherente entre SO.
- **Verificación de imagen**: releer y comparar hashes demuestra copia bit a bit, no solo "se copió".
- **Motor de informe agnóstico al SO**: los tres sistemas comparten la misma capa de timeline/HTML/JSON; cada plataforma solo aporta sus artefactos y hallazgos.

## Limitaciones

- **Prefetch** requiere PECmd (o Windows); si no, el `.pf` se adquiere pero no se interpreta.
- **Shimcache** cubre Windows 10/11 y 7.
- La adquisición de ficheros bloqueados / dispositivos requiere **admin/root** (y write-blocker en casos reales).
- **iOS**: un iPhone no ejecuta un colector propio; la vía viable es parsear un backup de Finder/iTunes (previsto como módulo aparte).
- El parseo de imágenes E01 requiere `libewf`; sin él, imaging cae a RAW.

## Licencia

MIT.
