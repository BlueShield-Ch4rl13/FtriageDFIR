"""Adaptador Windows: interfaz uniforme collect()/parse() sobre los módulos
existentes de recolección y parseo de Windows, para que el despachador trate a
los tres sistemas por igual.
"""
from __future__ import annotations

from pathlib import Path

from . import collectors, parsers

LABEL = "Windows"
CATEGORIES = collectors.CATEGORIES


def collect(root: Path, out_dir: Path, categories: list[str], opts=None) -> list[dict]:
    opts = opts or {}
    return collectors.collect_all(root, out_dir, categories, use_vss=opts.get("vss", False))


def parse(out_dir: Path, opts=None):
    """Devuelve (parsed, None). El None indica al informe que use los hallazgos
    por defecto basados en eventos de Windows (build_findings)."""
    opts = opts or {}
    parsed = parsers.parse_all(out_dir, opts.get("ez_tools"))
    return parsed, None
