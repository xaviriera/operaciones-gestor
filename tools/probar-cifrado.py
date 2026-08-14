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


def buscar_sobre(llavero: dict, alias: str) -> dict | None:
    for sobre in llavero["sobres"]:
        if sobre["alias"] == alias:
            return sobre
    return None


def exigir_abre(cifrador, llavero: dict, alias: str, password: str, datos_originales: bytes) -> None:
    sobre = buscar_sobre(llavero, alias)
    if sobre is None:
        raise AssertionError(f"no existe el sobre de {alias}")
    descifrado = descifrar_con_password(cifrador, llavero, sobre, password)
    if descifrado != datos_originales:
        raise AssertionError(f"el JSON descifrado para {alias} no coincide con el original")


def exigir_no_abre(cifrador, llavero: dict, alias: str, password: str, InvalidTag) -> None:
    sobre = buscar_sobre(llavero, alias)
    if sobre is None:
        return
    try:
        descifrar_con_password(cifrador, llavero, sobre, password)
    except InvalidTag:
        return
    raise AssertionError(f"el acceso {alias} se pudo abrir cuando debia fallar")


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
        tmp_path = Path(tmp)
        entrada = tmp_path / "operacion.json"
        resultado = cifrador.cifrar_operacion_bytes(datos_originales, participes)
        salida = tmp_path / "llavero.json"
        cifrador.escribir_llavero(salida, resultado.llavero)
        llavero = json.loads(salida.read_text(encoding="utf-8"))

        passwords = dict(resultado.passwords)
        correctas = 0
        fallos_limpios = 0
        for sobre in llavero["sobres"]:
            alias = sobre["alias"]
            exigir_abre(cifrador, llavero, alias, passwords[alias], datos_originales)
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

        entrada.write_bytes(datos_originales)
        definicion = tmp_path / "definicion-accesos-prueba.json"
        definicion.write_text(
            json.dumps(
                [
                    {"alias": "p-01", "password": "12345678A"},
                    {"alias": "p-02", "password": "clave elegida 77"},
                    {"alias": "p-03"},
                ],
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        salida_definida = tmp_path / "llavero-definido.json"
        codigo = cifrador.main(
            [
                "crear",
                "--entrada",
                str(entrada),
                "--salida",
                str(salida_definida),
                "--definicion-accesos",
                str(definicion),
                "--forzar",
            ]
        )
        if codigo != 0:
            print("ERROR: crear con fichero de definicion fallo.")
            return 1

        llavero_definido = json.loads(salida_definida.read_text(encoding="utf-8"))
        exigir_abre(cifrador, llavero_definido, "p-01", "12345678A", datos_originales)
        exigir_abre(cifrador, llavero_definido, "p-01", "12345678-a", datos_originales)
        exigir_abre(cifrador, llavero_definido, "p-01", "12345678 A", datos_originales)
        exigir_abre(cifrador, llavero_definido, "p-02", "clave elegida 77", datos_originales)

        antes_de_fallo = salida_definida.read_text(encoding="utf-8")
        codigo = cifrador.main(
            [
                "anadir",
                "--llavero",
                str(salida_definida),
                "--password-actual",
                "password equivocada",
                "--alias",
                "p-error",
                "--password",
                "87654321B",
            ]
        )
        if codigo == 0 or salida_definida.read_text(encoding="utf-8") != antes_de_fallo:
            print("ERROR: anadir con contrasena actual invalida modifico el llavero.")
            return 1

        codigo = cifrador.main(
            [
                "anadir",
                "--llavero",
                str(salida_definida),
                "--password-actual",
                "12345678-a",
                "--alias",
                "p-04",
                "--password",
                "87654321B",
            ]
        )
        if codigo != 0:
            print("ERROR: anadir acceso fallo.")
            return 1

        llavero_anadido = json.loads(salida_definida.read_text(encoding="utf-8"))
        exigir_abre(cifrador, llavero_anadido, "p-01", "12345678A", datos_originales)
        exigir_abre(cifrador, llavero_anadido, "p-02", "clave elegida 77", datos_originales)
        exigir_abre(cifrador, llavero_anadido, "p-04", "87654321B", datos_originales)

        codigo = cifrador.main(["quitar", "--llavero", str(salida_definida), "--alias", "p-02"])
        if codigo != 0:
            print("ERROR: quitar acceso fallo.")
            return 1

        llavero_quitado = json.loads(salida_definida.read_text(encoding="utf-8"))
        exigir_no_abre(cifrador, llavero_quitado, "p-02", "clave elegida 77", InvalidTag)
        exigir_abre(cifrador, llavero_quitado, "p-01", "12345678 A", datos_originales)
        exigir_abre(cifrador, llavero_quitado, "p-04", "87654321B", datos_originales)

    print("Prueba de cifrado completada correctamente.")
    print(f"Sobres verificados con contrasena correcta: {correctas}")
    print(f"Contrasenas incorrectas rechazadas limpiamente: {fallos_limpios}")
    print("Fichero de definicion con contrasenas elegidas: OK")
    print('Normalizacion DNI "12345678A" / "12345678-a" / "12345678 A": OK')
    print("Contrasena actual invalida no modifica el llavero: OK")
    print("Anadir acceso conserva sobres antiguos y abre el nuevo: OK")
    print("Quitar acceso elimina ese alias y conserva los demas: OK")
    print("El JSON descifrado coincide byte a byte con el original.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
