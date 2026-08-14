#!/usr/bin/env python3
"""
Prueba local del formato de cifrado usado por tools/cifrar-visor.py.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
from pathlib import Path


def cargar_cifrador():
    ruta = Path(__file__).resolve().with_name("cifrar-visor.py")
    spec = importlib.util.spec_from_file_location("cifrar_visor", ruta)
    if spec is None or spec.loader is None:
        raise RuntimeError("No puedo cargar tools/cifrar-visor.py")
    modulo = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = modulo
    spec.loader.exec_module(modulo)
    return modulo


def descifrar_con_password(cifrador, llavero: dict, sobre: dict, password: str) -> bytes:
    AESGCM, _PBKDF2HMAC, _hashes, _InvalidTag = cifrador.cargar_cryptography()
    clave_participe = cifrador.derivar_clave(password, cifrador.desde_b64(sobre["salt"]))
    clave_maestra = AESGCM(clave_participe).decrypt(
        cifrador.desde_b64(sobre["iv"]),
        cifrador.desde_b64(sobre["clave_cifrada"]),
        None,
    )
    return AESGCM(clave_maestra).decrypt(
        cifrador.desde_b64(llavero["contenido"]["iv"]),
        cifrador.desde_b64(llavero["contenido"]["datos"]),
        None,
    )


def main() -> int:
    cifrador = cargar_cifrador()
    _AESGCM, _PBKDF2HMAC, _hashes, InvalidTag = cifrador.cargar_cryptography()

    muestra = {
        "operacion": "Torres de Cotillas",
        "importe": 125000,
        "participes": ["Xavi", "Paco", "Antonio", "Dani"],
        "metricas": {"tir": 18.4, "plazo_meses": 14},
    }
    datos_originales = json.dumps(muestra, ensure_ascii=False, sort_keys=True).encode("utf-8")
    participes = ["Xavi", "Paco", "Antonio", "Dani"]

    with tempfile.TemporaryDirectory() as tmp:
        salida = Path(tmp) / "llavero.json"
        resultado = cifrador.cifrar_operacion_bytes(datos_originales, participes)
        cifrador.escribir_llavero(salida, resultado.llavero)
        llavero = json.loads(salida.read_text(encoding="utf-8"))

    passwords = dict(resultado.passwords)
    correctas = 0
    fallos_limpios = 0
    for sobre in llavero["sobres"]:
        alias = sobre["alias"]
        descifrado = descifrar_con_password(cifrador, llavero, sobre, passwords[alias])
        if descifrado != datos_originales:
            print(f"ERROR: el JSON descifrado para {alias} no coincide con el original.")
            return 1
        correctas += 1

        try:
            descifrar_con_password(cifrador, llavero, sobre, "password-incorrecto-99")
        except InvalidTag:
            fallos_limpios += 1
        except Exception as exc:
            print(f"ERROR: una contrasena incorrecta produjo un fallo inesperado para {alias}: {exc}")
            return 1
        else:
            print(f"ERROR: una contrasena incorrecta funciono para {alias}.")
            return 1

    print("Prueba de cifrado completada correctamente.")
    print(f"Sobres verificados con contrasena correcta: {correctas}")
    print(f"Contrasenas incorrectas rechazadas limpiamente: {fallos_limpios}")
    print("El JSON descifrado coincide byte a byte con el original.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
