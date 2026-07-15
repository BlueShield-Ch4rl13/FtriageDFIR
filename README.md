# DFIR Dashboard — dfir.carlosvillalbalagos.com

Capa de análisis del proyecto ftriage. Ingiere el `report.json` que genera el agente
`ftriage` en un equipo (Windows/Linux/macOS) y muestra el **veredicto de compromiso**,
el mapeo a **MITRE ATT&CK**, la **super-timeline**, todos los **artefactos**, los **IOCs**
y la **cadena de custodia**. Todo el análisis ocurre en el navegador: ningún dato sale del equipo.

## Modelo (agente → dashboard)

Una web no puede leer el kernel de un equipo remoto. El agente `ftriage` recolecta a nivel de
sistema (con privilegios) y produce `report.json`; este dashboard lo interpreta. Es el mismo
patrón que Velociraptor/GRR/TheHive: agente que recolecta + servidor/UI que analiza.

## Despliegue en Cloudflare Pages (igual que News CTI)

1. Sube esta carpeta a un repo (o conéctalo a Pages).
2. En Cloudflare Pages: proyecto nuevo → framework "None" → build vacío → output dir = raíz.
3. Custom domain → `dfir.carlosvillalbalagos.com`.
4. Es un sitio estático: `index.html` es autocontenido; `casos/` guarda ejemplos.

## Uso

- **Cargar report.json**: botón o arrastrar-soltar el fichero. Se interpreta al vuelo.
- **Caso de ejemplo**: veredicto de una intrusión Windows real (embebido).
- Para generar un caso: `python triage.py triage --case IR-XXXX` en el equipo objetivo → sube el `report.json`.

## Seguridad

- Sin backend ni base de datos: los informes forenses no se suben a ningún sitio.
- `_headers` fija una CSP estricta y cabeceras de seguridad para el despliegue en Pages.
