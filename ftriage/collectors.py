"""Recolección de artefactos forenses de Windows.

Copia cruda de cada artefacto a la carpeta del caso y construye el manifiesto
de cadena de custodia (ruta origen, hash SHA-256, tamaño, método y timestamp
de copia). No interpreta nada: eso es trabajo de parsers.py. El objetivo es
que la adquisición sea íntegra, auditable y tolerante a fallos — que un
artefacto bloqueado o ausente nunca tumbe la recolección completa.
"""
from __future__ import annotations

import logging
from pathlib import Path

from . import utils

log = logging.getLogger("ftriage")

# Canales de eventos de mayor valor en respuesta a incidentes. Se copian por
# nombre; los que no existan en el equipo se omiten silenciosamente.
EVENT_CHANNELS = [
    "Security.evtx",
    "System.evtx",
    "Application.evtx",
    "Microsoft-Windows-Sysmon%4Operational.evtx",
    "Microsoft-Windows-PowerShell%4Operational.evtx",
    "Windows PowerShell.evtx",
    "Microsoft-Windows-TaskScheduler%4Operational.evtx",
    "Microsoft-Windows-Windows Defender%4Operational.evtx",
    "Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx",
    "Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx",
    "Microsoft-Windows-WinRM%4Operational.evtx",
    "Microsoft-Windows-WMI-Activity%4Operational.evtx",
    "Microsoft-Windows-Bits-Client%4Operational.evtx",
]

# Categorías disponibles (para el flag --artifacts).
CATEGORIES = ["eventlogs", "prefetch", "amcache", "registry", "browsers"]


class Collector:
    """Enumera y copia los artefactos seleccionados desde un root de Windows.

    `root` es la raíz del sistema Windows: normalmente el disco vivo (C:\\),
    pero también puede apuntar a una imagen montada (p. ej. E:\\) para triage
    en frío.
    """

    def __init__(self, root: Path, out_dir: Path, categories: list[str],
                 shadow: "utils.ShadowCopy | None" = None):
        self.root = Path(root)
        self.artifacts_dir = out_dir / "artifacts"
        self.categories = categories
        self.shadow = shadow
        self.manifest: list[dict] = []

    # ---------------------------------------------------------- enumeración
    def _user_profiles(self) -> list[Path]:
        """Perfiles de usuario reales bajo \\Users, descartando los de sistema."""
        skip = {"All Users", "Default", "Default User", "Public",
                "defaultuser0", "WDAGUtilityAccount"}
        users_dir = self.root / "Users"
        if not users_dir.is_dir():
            return []
        return [p for p in users_dir.iterdir() if p.is_dir() and p.name not in skip]

    def _enumerate(self, category: str) -> list[Path]:
        """Rutas de origen existentes para una categoría."""
        r = self.root
        found: list[Path] = []

        if category == "eventlogs":
            base = r / "Windows" / "System32" / "winevt" / "Logs"
            found += [base / ch for ch in EVENT_CHANNELS]

        elif category == "prefetch":
            pf = r / "Windows" / "Prefetch"
            if pf.is_dir():
                found += sorted(pf.glob("*.pf"))

        elif category == "amcache":
            found.append(r / "Windows" / "AppCompat" / "Programs" / "Amcache.hve")

        elif category == "registry":
            cfg = r / "Windows" / "System32" / "config"
            # SYSTEM contiene el AppCompatCache (shimcache); el resto aporta
            # contexto (software instalado, cuentas, políticas).
            found += [cfg / h for h in ("SYSTEM", "SOFTWARE", "SAM", "SECURITY")]
            for prof in self._user_profiles():
                found.append(prof / "NTUSER.DAT")
                found.append(prof / "AppData" / "Local" / "Microsoft" / "Windows" / "UsrClass.dat")

        elif category == "browsers":
            for prof in self._user_profiles():
                la = prof / "AppData" / "Local"
                ro = prof / "AppData" / "Roaming"
                # Chrome y Edge: un fichero History por perfil del navegador
                for vendor, sub in (("Google", "Chrome"), ("Microsoft", "Edge")):
                    udata = la / vendor / sub / "User Data"
                    if udata.is_dir():
                        for bp in udata.iterdir():
                            hist = bp / "History"
                            if hist.is_file():
                                found.append(hist)
                # Firefox: places.sqlite por perfil
                ff = ro / "Mozilla" / "Firefox" / "Profiles"
                if ff.is_dir():
                    found += sorted(ff.glob("*/places.sqlite"))

        # Solo lo que exista de verdad (los canales de evento inexistentes caen aquí)
        return [p for p in found if p.exists()]

    # ---------------------------------------------------------- recolección
    def collect(self) -> list[dict]:
        """Copia todos los artefactos seleccionados y devuelve el manifiesto."""
        for category in self.categories:
            sources = self._enumerate(category)
            if not sources:
                log.info("[%s] sin artefactos encontrados", category)
                continue
            log.info("[%s] recolectando %d artefacto(s)", category, len(sources))
            dest_dir = self.artifacts_dir / category
            for src in sources:
                self._collect_one(category, src, dest_dir)
        ok = sum(1 for e in self.manifest if e["status"] == "ok")
        log.info("Recolección terminada: %d/%d artefactos copiados",
                 ok, len(self.manifest))
        return self.manifest

    def _nombre_destino(self, category: str, src: Path) -> str | None:
        """Nombre en la carpeta del caso para lo que se repite entre perfiles.

        Antes solo los navegadores llevaban el usuario en el nombre: los
        NTUSER.DAT de todos los usuarios se copiaban como "NTUSER.DAT" y solo
        sobrevivía el último, con un manifiesto que listaba copias que ya no
        existían.
        """
        try:
            user = src.relative_to(self.root / "Users").parts[0]
        except ValueError:
            return None
        if category == "browsers":
            return f"{user}_{src.parent.name}_{src.name}"
        return f"{user}_{src.name}"

    def _collect_one(self, category: str, src: Path, dest_dir: Path) -> None:
        nombre = self._nombre_destino(category, src)
        for ruta, rn in utils.con_companeros([(src, nombre)]):
            entry = utils.copy_and_record(category, ruta, dest_dir, self.manifest, rn, self.shadow)
            if entry["status"] != "ok":
                log.warning("No se pudo copiar %s: %s", ruta, entry.get("error", ""))


def collect_all(root: Path, out_dir: Path, categories: list[str],
                use_vss: bool = False) -> list[dict]:
    """Punto de entrada de recolección, con o sin instantánea VSS."""
    if use_vss:
        drive = f"{str(root)[:2]}\\" if str(root)[1:2] == ":" else "C:\\"
        with utils.ShadowCopy(drive) as shadow:
            return Collector(root, out_dir, categories, shadow).collect()
    return Collector(root, out_dir, categories).collect()
