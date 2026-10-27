#!/usr/bin/env python3
"""Pruebas aisladas: todos los datos y recursos se inventan en un temporal."""
import contextlib
import functools
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("comercial", Path(__file__).with_name("generar-visor-comercial.py"))
g = importlib.util.module_from_spec(spec)
spec.loader.exec_module(g)


class ComercialTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="visor-comercial-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.origen = self.root / "entrada.json"
        self.salida = self.root / "privado"
        self.destino = self.root / "publico"
        self.assets = self.root / "recursos"
        self.assets.mkdir()
        (self.assets / "plano.svg").write_text('<svg xmlns="http://www.w3.org/2000/svg" width="80" height="80"><rect width="80" height="80" fill="navy"/></svg>')
        (self.assets / "logo-cdu-blanco.png").write_bytes(b"synthetic")
        self.datos = {
            "operacion": {"nombre": "Promoción ficticia", "direccion": "Calle Inventada 1", "resumen_una_linea": "Prueba sintética"},
            "estado": {"fases": [], "fase_actual": "Obra"},
            "planos": [{"fichero": "plano.svg", "nombre": "Plano ficticio"}],
            "cuentas": {"iban": "IBAN-FICTICIO", "saldo": "123", "tramos": []},
            "documentacion": [], "escenario_economico": {"inversion_total": "456"},
            "proximo_reporte": {"fecha": "2099-01-01", "texto": "Reunión ficticia"},
            "contacto": {"whatsapp": "34000000000"},
        }
        self.origen.write_text(json.dumps(self.datos), encoding="utf-8")
        self.args = ["--origen", str(self.origen), "--salida-dir", str(self.salida)]
        self.env = patch.dict(os.environ, {"VISOR_COMERCIAL_PASSWORD": "Prueba-Sintetica.42"})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.asset_patch = patch.object(g, "ASSETS", self.assets)
        self.asset_patch.start()
        self.addCleanup(self.asset_patch.stop)

    def ejecutar(self, *extra):
        with contextlib.redirect_stdout(io.StringIO()) as captura:
            self.assertEqual(g.main(self.args + list(extra)), 0)
        return captura.getvalue()

    def llavero(self):
        return g.cifrar.leer_llavero(self.salida / "llavero.json")

    def test_filtro(self):
        filtro = json.loads((g.RAIZ / "tools/filtro-visor-comercial.json").read_text(encoding="utf-8"))
        filtro["renombrar_hitos"] = {"Grupo inversor": "Preparación"}
        filtro["detalle_hitos"] = {"Grupo inversor": "Documentos preparados", "Entrega": ""}
        filtro["excluir_bitacora_titulos"] = ["Título exacto"]
        ruta = self.root / "filtro.json"
        ruta.write_text(json.dumps(filtro), encoding="utf-8")
        self.datos.update({
            "bitacora": [{"titulo": "Coste", "texto": "100 €"},
                         {"titulo": "Obra", "texto": "Tabiques terminados"},
                         {"titulo": "Título exacto", "texto": "Nota"},
                         {"titulo": "INVERSIÓN", "texto": "Nota"}],
            "hitos": [{"nombre": "Grupo inversor", "detalle": "Partícipes", "peso": 20, "estado": "conseguido", "fase": "Inicio"},
                      {"nombre": "Obra", "detalle": "COMISION bancaria abonada", "peso": 50, "estado": "actual", "fase": "Obra"},
                      {"nombre": "Entrega", "detalle": "Texto sustituible", "peso": 30, "estado": "pendiente", "fase": "Final"}],
            "contacto": {"mensaje_predeterminado": "Soy inversor", "whatsapp_numero": "123.45"},
            "camaras": [{"url": "https://example.invalid/123.45"}],
            "fotos_avance": [{"url": "https://example.invalid/123.45"}],
            "planos": [{"fichero": "123.45.svg"}],
            "noticias_mercado": [{"enlace": "https://example.invalid/123.45"}],
        })
        self.origen.write_text(json.dumps(self.datos), encoding="utf-8")
        resumen = self.ejecutar("--filtro", str(ruta))
        salida = json.loads((self.salida / "operacion.json").read_text(encoding="utf-8"))
        self.assertEqual(salida["bitacora"], [self.datos["bitacora"][1]])
        self.assertEqual(salida["hitos"][0]["nombre"], "Preparación")
        self.assertEqual([h["detalle"] for h in salida["hitos"]], ["Documentos preparados", "", ""])
        self.assertEqual(len(salida["hitos"]), len(self.datos["hitos"]))
        self.assertEqual(salida["estado"], self.datos["estado"])
        for antes, despues in zip(self.datos["hitos"], salida["hitos"]):
            for clave in ("peso", "estado", "fase"):
                self.assertEqual(antes[clave], despues[clave])
        self.assertEqual(salida["contacto"]["mensaje_predeterminado"], filtro["contacto_mensaje"])
        self.assertIn("Bitácoras eliminadas: 3; hitos renombrados: 1; detalles vaciados: 2", resumen)

    def test_rechazo_sin_escritura(self):
        self.datos["hitos"] = [{"nombre": "INVERSIÓN privada", "detalle": ""}]
        self.datos["extra"] = {"anidado": ["Saldo bancario", "123.45"]}
        self.origen.write_text(json.dumps(self.datos), encoding="utf-8")
        for preexistente in (False, True):
            if preexistente:
                self.salida.mkdir()
                self.destino.mkdir()
                (self.salida / "operacion.json").write_bytes(b"sintetico anterior")
                (self.destino / "index.html").write_bytes(b"publicacion anterior")
            antes = {p: p.read_bytes() for p in self.root.rglob("*") if p.is_file()}
            resultado = subprocess.run([sys.executable, str(Path(g.__file__)), *self.args,
                                       "--publicar-en", str(self.destino)], capture_output=True, text=True, encoding="utf-8",
                                      env={**os.environ, "PYTHONIOENCODING": "utf-8"})
            self.assertEqual(resultado.returncode, 1)
            for ruta in ("hitos[0].nombre", "extra.anidado[0]", "extra.anidado[1]"):
                self.assertIn(ruta, resultado.stderr)
            self.assertIn("INVERSIÓN privada", resultado.stderr)
            self.assertEqual(antes, {p: p.read_bytes() for p in self.root.rglob("*") if p.is_file()})
            if not preexistente:
                self.assertFalse(self.salida.exists())
                self.assertFalse(self.destino.exists())

    def test_cifrado_y_actualizacion(self):
        self.ejecutar()
        primero = self.llavero()
        self.assertEqual(primero["iteraciones"], 250000)
        self.assertEqual([s["alias"] for s in primero["sobres"]], ["rp-01"])
        clave = g.cifrar.abrir_clave_maestra(primero, "prueba sintetica42")
        AESGCM, *_ = g.cifrar.cargar_cryptography()
        plano = AESGCM(clave).decrypt(g.cifrar.desde_b64(primero["contenido"]["iv"]), g.cifrar.desde_b64(primero["contenido"]["datos"]), None)
        datos = json.loads(plano)
        self.assertFalse(set(g.PRIVADAS) & datos.keys())
        self.assertEqual(datos["modo_comercial"], {"etiqueta": g.ETIQUETA, "pie_legal": g.PIE_LEGAL})
        self.assertEqual(plano, (self.salida / "operacion.json").read_bytes())
        self.datos["operacion"]["nombre"] = "Cambio inventado"
        self.origen.write_text(json.dumps(self.datos), encoding="utf-8")
        self.ejecutar()
        segundo = self.llavero()
        self.assertEqual(primero["sobres"], segundo["sobres"])
        self.assertEqual(clave, g.cifrar.abrir_clave_maestra(segundo, "prueba sintetica42"))
        self.assertNotEqual(primero["contenido"]["iv"], segundo["contenido"]["iv"])
        for password in ("", "incorrecta"):
            with patch.dict(os.environ, {"VISOR_COMERCIAL_PASSWORD": password}):
                with self.assertRaises(ValueError):
                    self.ejecutar()
            self.assertEqual(segundo, self.llavero())

    def test_password_generada_una_vez(self):
        with patch.dict(os.environ, {"VISOR_COMERCIAL_PASSWORD": ""}):
            mensaje = self.ejecutar()
        password = mensaje.split("(guárdala ahora): ")[1].splitlines()[0]
        self.assertEqual(mensaje.count(password), 1)
        g.cifrar.abrir_clave_maestra(self.llavero(), password)
        with patch.dict(os.environ, {"VISOR_COMERCIAL_PASSWORD": password}):
            self.assertNotIn(password, self.ejecutar())

    def test_publicacion_y_seguridad(self):
        self.assertEqual(list(g.referencias_locales({"fecha": "27.10.2026", "texto": "Ver plano.pdf", "url": "https://example.invalid/foto.jpg"})), [])
        self.ejecutar("--publicar-en", str(self.destino))
        html = (self.destino / "index.html").read_text(encoding="utf-8")
        self.assertIn(f"const ORIGEN_LLAVERO = '{g.URL_LLAVERO}';", html)
        self.assertIn("const ORIGEN_DATOS = '';", html)
        self.assertEqual((self.destino / "llavero.json").read_bytes(), (self.salida / "llavero.json").read_bytes())
        (self.destino / "plano.svg").write_text("conservar")
        self.ejecutar("--publicar-en", str(self.destino))
        self.assertEqual((self.destino / "plano.svg").read_text(), "conservar")
        with self.assertRaises(ValueError):
            g.comprobar_publicacion(self.destino, "const ORIGEN_DATOS = 'operacion.json';")
        carpeta = self.destino / "anidado"
        carpeta.mkdir()
        (carpeta / "operacion.json").write_text("{}")
        with self.assertRaises(ValueError):
            self.ejecutar("--publicar-en", str(self.destino))
        with self.assertRaises(ValueError):
            list(g.referencias_locales({"fichero": "../secreto.pdf"}))

    def test_navegador(self):
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            self.skipTest("Playwright no instalado; ejecutar tras instalarlo para verificar DOM y capturas.")
        self.ejecutar()
        actual = (g.RAIZ / "torres-cotillas/visor/index.html").read_text(encoding="utf-8")
        anterior = subprocess.check_output(["git", "show", "HEAD:torres-cotillas/visor/index.html"], cwd=g.RAIZ).decode("utf-8")
        comercial = json.loads((self.salida / "operacion.json").read_text(encoding="utf-8"))
        for nombre, html, datos in (("antes", anterior, self.datos), ("participes", actual, self.datos), ("comercial", actual, comercial)):
            carpeta = self.root / nombre
            carpeta.mkdir()
            html = re.sub(r"const ORIGEN_DATOS = '[^']*';", "const ORIGEN_DATOS = 'sintetico.json';", html)
            (carpeta / "index.html").write_text(html, encoding="utf-8")
            (carpeta / "sintetico.json").write_text(json.dumps(datos), encoding="utf-8")
            (carpeta / "plano.svg").write_bytes((self.assets / "plano.svg").read_bytes())
        class Silencioso(SimpleHTTPRequestHandler):
            def log_message(self, *args):
                pass
        servidor = ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(Silencioso, directory=str(self.root)))
        hilo = threading.Thread(target=servidor.serve_forever, daemon=True)
        hilo.start()
        self.addCleanup(servidor.server_close)
        self.addCleanup(servidor.shutdown)
        capturas = Path(tempfile.mkdtemp(prefix="visor-comercial-capturas-"))
        with sync_playwright() as pw:
            browser = pw.chromium.launch()
            try:
                for ancho in (1440, 390):
                    pagina = browser.new_page(viewport={"width": ancho, "height": 900})
                    pagina.route(re.compile(r"https?://(?!127\.0\.0\.1)"), lambda route: route.abort())
                    errores = []
                    pagina.on("pageerror", lambda error: errores.append(str(error)))
                    imagenes = []
                    for nombre in ("antes", "participes", "comercial"):
                        pagina.goto(f"http://127.0.0.1:{servidor.server_port}/{nombre}/index.html?claro=1")
                        pagina.locator("#operationName").wait_for()
                        pagina.wait_for_timeout(700)
                        self.assertFalse(pagina.locator("#dataWarning").is_visible())
                        for selector in ("#cuentas", "#documentacion", "#nextReport", "#escenarioEconomicoSection"):
                            self.assertEqual(pagina.locator(selector).is_visible(), nombre != "comercial")
                        if nombre == "comercial":
                            self.assertEqual(pagina.locator("#commercialBanner").inner_text(), g.ETIQUETA)
                            self.assertEqual(pagina.locator("footer.legal").inner_text(), g.PIE_LEGAL)
                            pagina.evaluate("window.scrollTo(0, 800)")
                            self.assertEqual(pagina.locator("#commercialBanner").bounding_box()["y"], 0)
                            pagina.evaluate("window.scrollTo(0, 0)")
                            descifrado = pagina.evaluate("async ({llavero,password}) => descifrarContenido(llavero, await obtenerClaveMaestra(password,llavero))", {"llavero": self.llavero(), "password": "prueba sintetica42"})
                            self.assertEqual(descifrado, comercial)
                        else:
                            self.assertEqual(pagina.locator("#commercialBanner").count(), 0)
                        imagenes.append(pagina.screenshot(path=str(capturas / f"{nombre}-{ancho}.png"), full_page=True, animations="disabled"))
                    self.assertTrue(imagenes[0] == imagenes[1], "El visor de partícipes debe mantener exactamente su aspecto")
                    self.assertEqual(errores, [])
                    pagina.close()
            finally:
                browser.close()
        print(f"Capturas: {capturas}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
