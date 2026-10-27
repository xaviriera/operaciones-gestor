#!/usr/bin/env python3
"""Genera y publica el visor comercial sin alterar los accesos existentes."""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import sys
from urllib.parse import unquote, urlsplit

RAIZ = Path(__file__).resolve().parents[1]
ASSETS = RAIZ.parent / "cdu-visor" / "tdc"
URL_LLAVERO = "https://visor.tucambiodeuso.com/tdc-comercial/llavero.json"
PRIVADAS = ("escenario_economico", "cuentas", "documentacion", "proximo_reporte")
ETIQUETA = "Solo para uso comercial · Rosa & Porta"
PIE_LEGAL = "Información orientativa sobre el estado de la obra y de la promoción, facilitada exclusivamente para su comercialización. No constituye oferta vinculante ni sustituye a la documentación contractual. © CdU DE 0 A ÉXITO, S.L."

spec = importlib.util.spec_from_file_location("cifrar_visor", Path(__file__).with_name("cifrar-visor.py"))
cifrar = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = cifrar
spec.loader.exec_module(cifrar)


def comprobar_publicacion(destino: Path, html: str) -> None:
    origen = re.search(r"const\s+ORIGEN_DATOS\s*=\s*(['\"])(.*?)\1", html)
    if not origen or "operacion.json" in origen[2].lower():
        raise ValueError("Publicación insegura: ORIGEN_DATOS contiene operacion.json o no existe.")
    if destino.exists() and any(p.name.lower() == "operacion.json" for p in destino.rglob("*")):
        raise ValueError("Publicación insegura: el destino contiene operacion.json.")


def referencias_locales(datos, es_referencia=False):
    """Recorre referencias de archivos, incluidas rutas con query o fragmento."""
    if isinstance(datos, dict):
        for clave, valor in datos.items():
            referencia = clave in {"fichero", "archivo", "ruta", "src", "href", "url"} or clave.startswith("url_")
            if isinstance(valor, (dict, list)) or referencia:
                yield from referencias_locales(valor, referencia)
    elif isinstance(datos, list):
        for valor in datos:
            yield from referencias_locales(valor, es_referencia)
    elif isinstance(datos, str) and es_referencia:
        url = urlsplit(datos)
        if url.scheme or url.netloc or not url.path or url.path.startswith("/"):
            return
        ruta = Path(unquote(url.path))
        if ruta.is_absolute() or ".." in ruta.parts or "\\" in datos:
            raise ValueError("Referencia local fuera de la carpeta de publicación.")
        if ruta.name.lower() in {"operacion.json", "llavero.json", "index.html"}:
            raise ValueError("Referencia local reservada para datos o publicación.")
        yield ruta


def preparar_publicacion(destino: Path, datos: dict, assets: Path):
    html = (RAIZ / "torres-cotillas/visor/index.html").read_text(encoding="utf-8")
    for nombre, valor in (("ORIGEN_LLAVERO", URL_LLAVERO), ("ORIGEN_DATOS", "")):
        html, cantidad = re.subn(rf"const {nombre} = '[^']*';", f"const {nombre} = '{valor}';", html)
        if cantidad != 1:
            raise ValueError(f"No se encuentra una única constante {nombre}.")
    comprobar_publicacion(destino, html)
    copias = []
    referencias = set(referencias_locales(datos))
    # El logo también es necesario para la pantalla de acceso de la plantilla.
    referencias.add(Path("logo-cdu-blanco.png"))
    for relativa in sorted(referencias):
        salida = destino / relativa
        if not salida.resolve().is_relative_to(destino.resolve()):
            raise ValueError("Destino de recurso fuera de la publicación.")
        if salida.exists():
            continue
        origen = assets / relativa
        if not origen.resolve().is_relative_to(assets.resolve()):
            raise ValueError("Origen de recurso fuera de la carpeta de recursos.")
        if not origen.is_file():
            raise FileNotFoundError(f"Falta el recurso local: {relativa}")
        copias.append((origen, salida))
    return html, copias


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--origen", type=Path, default=RAIZ / "data/tdc/operacion.json")
    parser.add_argument("--salida-dir", type=Path, default=RAIZ / "data/tdc-comercial")
    parser.add_argument("--publicar-en", type=Path)
    parser.add_argument("--etiqueta", default=ETIQUETA)
    parser.add_argument("--pie-legal", default=PIE_LEGAL)
    args = parser.parse_args(argv)
    salida = args.salida_dir.resolve()
    destino = args.publicar_en.resolve() if args.publicar_en else None
    if args.origen.resolve() == salida / "operacion.json":
        raise ValueError("El origen y la copia comercial deben ser distintos.")
    if destino and (salida.is_relative_to(destino) or destino.is_relative_to(salida)):
        raise ValueError("Separa la carpeta privada de la carpeta de publicación.")
    datos = json.loads(args.origen.read_text(encoding="utf-8"))
    if not isinstance(datos, dict):
        raise ValueError("El origen debe ser un objeto JSON.")
    for clave in PRIVADAS:
        datos.pop(clave, None)
    datos["modo_comercial"] = {"etiqueta": args.etiqueta, "pie_legal": args.pie_legal}
    plano = (json.dumps(datos, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    publicacion = preparar_publicacion(destino, datos, ASSETS) if destino else None
    password = os.environ.get("VISOR_COMERCIAL_PASSWORD")
    ruta_llavero = salida / "llavero.json"
    generada = False
    if ruta_llavero.exists():
        if not password:
            raise ValueError("VISOR_COMERCIAL_PASSWORD es obligatoria para recifrar.")
        llavero = cifrar.leer_llavero(ruta_llavero)
        if [s.get("alias") for s in llavero["sobres"]] != ["rp-01"]:
            raise ValueError("Se esperaba un único sobre comercial rp-01.")
        maestra = cifrar.abrir_clave_maestra(llavero, password)
        AESGCM, *_ = cifrar.cargar_cryptography()
        iv = secrets.token_bytes(12)
        llavero["contenido"] = {"iv": cifrar.b64(iv), "datos": cifrar.b64(AESGCM(maestra).encrypt(iv, plano, None))}
    else:
        if not password:
            password = cifrar.generar_password()
            generada = True
        if not cifrar.normalizar_password(password):
            raise ValueError("La contraseña normalizada no puede estar vacía.")
        llavero = cifrar.cifrar_operacion_bytes(plano, [cifrar.DefinicionAcceso("rp-01", password)]).llavero
    salida.mkdir(parents=True, exist_ok=True)
    (salida / "operacion.json").write_bytes(plano)
    cifrar.escribir_llavero(ruta_llavero, llavero)
    if generada:
        print(f"Contraseña rp-01 (guárdala ahora): {password}")
    if publicacion:
        html, copias = publicacion
        destino.mkdir(parents=True, exist_ok=True)
        for origen, archivo in copias:
            archivo.parent.mkdir(parents=True, exist_ok=True)
            if not archivo.exists():
                shutil.copy2(origen, archivo)
        (destino / "index.html").write_text(html, encoding="utf-8")
        shutil.copy2(ruta_llavero, destino / "llavero.json")
        comprobar_publicacion(destino, (destino / "index.html").read_text(encoding="utf-8"))
    print("Visor comercial generado correctamente.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(1)
