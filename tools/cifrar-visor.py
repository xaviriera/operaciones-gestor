#!/usr/bin/env python3
"""
Cifra los datos de una operacion para publicarlos en una web estatica.

Formato de salida pactado con el visor del navegador:
- El JSON completo se cifra con una clave maestra aleatoria usando AES-256-GCM.
- Cada participe recibe un sobre: su contrasena deriva una clave PBKDF2 que cifra
  la clave maestra, tambien con AES-256-GCM.
- En todos los cifrados AES-GCM, cryptography devuelve ciphertext + tag.
"""

from __future__ import annotations

import argparse
import base64
import json
import math
import secrets
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


ITERACIONES = 250_000
FICHERO_PASSWORDS = "CONTRASENAS-participes-NO-SUBIR.txt"
DIGITOS_SEGUROS = "23456789"

# Palabras espanolas ASCII, cortas y legibles. Se evitan acentos, enes con tilde,
# guiones internos y terminos con caracteres que suelen confundirse con cifras.
PALABRAS = """
abeja abrazo abrigo abril abuelo abuso aceite acero actor acto adorno adulto
afecto aforo agenda agosto agua aguja ahorro aire aldea alegro alerta alfombra
algodon alianza alivio alma almendra altar altura alumno amargo amigo amor ancho
andamio angel anillo animo anuncio apio apoyo arbol arena armario aroma arroz
arte asa asado atajo atleta atun aula autor avance avion ayuda azucar barco
barrio baston batalla bebe belleza beso biblioteca billete blanco bloque boca
bodega bolsa bomba bondad bosque boton brasa brazo brisa brote bucle bueno
bufanda buzon caballo cabina cable cacao cadena cafe caja calma camino campo
canal cancion candado canela canguro canon canto capitan cara carbon cardo
carga caricia carne carpeta carro carta casa cascada caso castillo causa cebolla
cedro cielo cifra cima cine cinta circo ciudad claro clase clave cliente clima
cobre cocina codigo cofre colina color comida compra coral corona correo cosecha
costa cristal cuadro cuarto cubo cuchara cuello cuenta cueva cultura cumbre
dama dato deber dedo defensa delito deporte deseo detalle deuda dia diario dibujo
dicha diente dinero disco diseno doble doctor dolor domingo dragon ducha dueno
dulce eco edad edificio ejemplo eleccion elogio embudo empleo energia enero
enlace ensayo entrada equipo escala escena escuela esfera espejo espuma esquina
estado estrella estudio etapa exito familia faro favor febrero fecha feria finca
flor fondo forma foto frase fruta fuego fuente fuerza futuro gallo garaje gato
gemelo gente giro globo golpe goma gorra gota grado grano grupo guante guerra
guia gusto haba habitacion harina hielo hierro hijo historia hoja hombre honor
hora hotel hueso humo idea idioma imagen impulso indice isla jardin jarra jefe
juego julio junio junta lado lago lana lapiz largo lata lectura leche leccion
lengua lente libro lima limite limpio linea lista llave lluvia local logro luna
luz madera madre maleta mano mapa marzo masa mayo medida memoria mesa metal
metro miedo miel minuto mirada moda modelo molino momento moneda monte motor
mueble mujer mundo mural musica nave negocio noche norma nota nube numero obra
ocio oferta oficio ojo ola olivo orden oreja origen oro otono pagina pago palabra
palacio papel parque parte paso patio pausa paz pedido perfil perla perro peso
piedra pieza pintura piso pista plaza poder poema polvo portal precio premio
prensa prueba pueblo puente puerta punto queso rabia radio rama rato rayo razon
recibo regla reloj renta reserva reto rio roca rueda ruta sabado salon salto
sangre santo secado seda sello semana senda serie silla simbolo sitio socio sol
sonido sopa suerte suelo sueno tabla tarde tarifa taza teatro techo tela tema
tienda tierra timbre tipo toro torre trabajo trato tren tribu trigo turno union
urna uso valle valor vapor vaso vela verano verde viaje vida vidrio viento vino
vista vivienda voz vuelo zona
abierto abono abridor abuela acuerdo afable agencia agilidad aguila alamo albino
alcance alegria aliento almacen amparo ancla antena arenares armonia arreglo
artista asiento asunto ataque azafran azotea bahia balcon baliza bambu bandera
banquete barato barniz barrera bateria beisbol berenjena biberon bloqueador
bolero bombilla bonanza bordado botella brecha bronce brocha burbuja cabecera
cabrera cadenares cajero calabaza caldera calendario calidad camada cambio
camisa campana cantera capilla capricho caramelo caravana carrera cartera casero
castano cazuela celeste cemento ceniza centro cepillo cereza cerrado cesta chapa
chiste choque ciclo cilindro ciruela clavel coleta colegio columna comarca cometa
comienzo compania conejo consejo consuelo contrato copla coraje corazon cordon
cornisa cortina cosechero credito cresta cubierta cuchillo cultivo damares
decoro decreto defensares demanda deposito descanso destino dibujores domingo
dorado durazno economia edicion efecto elefante embalse empuje encargo encanto
energiares escalera escudo esencia estanco estanque estreno fachada factura
famoso farola febrerores firmeza flamenco flecha florero fogon forja fortuna
fresco frontera galeria gallina garganta garrafa gaveta gigante girasol guitarra
granada granizo hacienda hallazgo hazana herida herrero hoguera hormiga huella
huerto infancia ingreso jabon jabonera jazmin jornada judia jugada ladrillo
laguna lampara lanza lealtad lejano lenteja leonera libreta licencia ligereza
limonero linterna llanura maderares madrina malaga manana mandarina manilla
marcado margen marina medalla mejilla mercado merienda milagro mochila monedares
montana mosaico motivo naranja negociores nevera nublado octubre oficina oliva
orilla paquete parcela pareja pasillo pastilla peaje peligro pendiente pepino
perdiz permiso piscina planeta poblado poquito portada potencia pradera pregunta
primavera progreso promesa proyecto pulsera puntada racimo recurso refugio
regalo regreso remanso reparto respeto revista rodillo romero rosal salario
salsa saludo sandalia secreto semilla senal sendero sereno silbato simpleza
sobrino solapa solera sombra sonrisa soplido subida taberna tablero talento
tamano tapete teclado terraza tesoro tijera tomate trabajo teatrores trenza
tulipan umbral universo utensilio valija ventaja ventana verdad vestido victoria
viernes vineta volumen zapato zocalo
""".split()

RAICES_LEGIBLES = """
abac abed abog abon abord abraz abrig abrillant absolut absurd abund acab aceit
acer acerc aclar acog acomod acompan aconsej acord acort activ actu adapt adecu
adivin admir adorn adquir advert afirm agil agot agrad agrup agu aguac agud ahorr
aisl ajust alab alarm alegr alej aliger aliment aline aloj altern alumbr alz amabl
amanec amarill ambient ampli analiz ancl anim anunci apag aparat aparc apart apel
apetec aplic aport apoy aprend aprob aprovech apunt arbor archiv arregl arriesg
arrop asegur asfalt aspir asombr atent aterriz atesor aument avanz avis ayud baj
balanc ban barr bast bell bend benefici blanc blind bocet bord brill brom busc
cabalg cabin calcul calent call cambi camin camp cant capacit carg cari cas cement
centr cerr chap charl choc circul cit clar clasific clav cobr cocin coloc combin
coment comerci compar compart complet compr comunic conced conect confi confirm
conserv consider consolid consult cont contest contrat control convid copi coron
correg cort cos cosech cuid cumpl curv decor dedic defens dej descans descubiert
despej destin detall dibuj disfrut divid dobl dor dur educ elabor elev eleg empez
emple encaj encend encontr enfoc enfri entreg envi equilibr escap escog escond
escrib escuch esper estabil estim estudi evit examin explic explor facilit factur
fall fals famili fascin favor felicit fij final firm flot form fotograf fres gan
gast gener gobern grab guard habl habit habil hall hech hel horne ilumin imagin
implic impuls indic inform inici invit junt justific labor lav levant limpi llev
localiz logr madur manej marc medit mejor mezcl mir model modern mont mostr naveg
necesit negoci nombr observ ocup ofrec orden organiz orient pag particip pas pase
patent paus pens perdon permit pint prepar present prest prob proces produc program
proteg public pul repart respet respir result reun revis rod salud salt sembr senal
separ situ solucion son sobr solicit subray sumin sum sup tabl tapiz termin toc
trabaj traz ubic unific us valor viaj vigil vincul visit vot zanj
""".split()

SUFIJOS_LEGIBLES = """
a able ada ado aje al ancia ante ar aria ario ble cion da dad do dor dora dura
e eda edo ente eria ero era ez ido ida il ismo ista ivo iva izo iza mente or osa
oso ura
""".split()

PALABRAS = sorted(
    set(
        PALABRAS
        + [
            raiz + sufijo
            for raiz in RAICES_LEGIBLES
            for sufijo in SUFIJOS_LEGIBLES
            if 5 <= len(raiz + sufijo) <= 14
        ]
    )
)


@dataclass(frozen=True)
class ResultadoCifrado:
    llavero: dict
    passwords: list[tuple[str, str]]


class ParserEspanol(argparse.ArgumentParser):
    def format_usage(self) -> str:
        return super().format_usage().replace("usage:", "uso:")

    def format_help(self) -> str:
        return super().format_help().replace("usage:", "uso:").replace("options:", "opciones:")

    def error(self, message: str) -> None:
        traducciones = (
            ("the following arguments are required:", "faltan argumentos obligatorios:"),
            ("unrecognized arguments:", "argumentos no reconocidos:"),
            ("expected one argument", "falta un valor"),
            ("invalid choice:", "opcion no valida:"),
        )
        for original, traducido in traducciones:
            message = message.replace(original, traducido)
        self.print_usage(sys.stderr)
        raise SystemExit(f"Error: {message}")


def cargar_cryptography():
    try:
        from cryptography.exceptions import InvalidTag
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    except ModuleNotFoundError as exc:
        if exc.name == "cryptography":
            print(
                "Falta el paquete 'cryptography'. Instalalo con:\n\n"
                "    python -m pip install cryptography\n",
                file=sys.stderr,
            )
            raise SystemExit(1) from exc
        raise
    return AESGCM, PBKDF2HMAC, hashes, InvalidTag


def b64(datos: bytes) -> str:
    return base64.b64encode(datos).decode("ascii")


def desde_b64(texto: str) -> bytes:
    return base64.b64decode(texto.encode("ascii"), validate=True)


def parsear_participes(texto: str) -> list[str]:
    participes = [p.strip() for p in texto.split(",") if p.strip()]
    if not participes:
        raise ValueError("Indica al menos un participe en --participes, separado por comas.")
    vistos: set[str] = set()
    repetidos = [p for p in participes if p.casefold() in vistos or vistos.add(p.casefold())]
    if repetidos:
        raise ValueError("Hay participes repetidos. Deja cada alias una sola vez.")
    return participes


def entropia_password() -> float:
    return 4 * math.log2(len(PALABRAS)) + math.log2(len(DIGITOS_SEGUROS) ** 2)


def generar_password() -> str:
    palabras = [secrets.choice(PALABRAS) for _ in range(4)]
    digitos = "".join(secrets.choice(DIGITOS_SEGUROS) for _ in range(2))
    return "-".join(palabras) + digitos


def derivar_clave(password: str, salt: bytes) -> bytes:
    AESGCM, PBKDF2HMAC, hashes, _InvalidTag = cargar_cryptography()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERACIONES,
    )
    return kdf.derive(password.encode("utf-8"))


def cifrar_operacion_bytes(datos_json: bytes, participes: Iterable[str]) -> ResultadoCifrado:
    AESGCM, _PBKDF2HMAC, _hashes, _InvalidTag = cargar_cryptography()

    clave_maestra = secrets.token_bytes(32)
    iv_contenido = secrets.token_bytes(12)
    datos_cifrados = AESGCM(clave_maestra).encrypt(iv_contenido, datos_json, None)

    sobres = []
    passwords: list[tuple[str, str]] = []
    for alias in participes:
        password = generar_password()
        salt = secrets.token_bytes(16)
        clave_participe = derivar_clave(password, salt)
        iv_sobre = secrets.token_bytes(12)
        clave_cifrada = AESGCM(clave_participe).encrypt(iv_sobre, clave_maestra, None)
        sobres.append(
            {
                "alias": alias,
                "salt": b64(salt),
                "iv": b64(iv_sobre),
                "clave_cifrada": b64(clave_cifrada),
            }
        )
        passwords.append((alias, password))

    return ResultadoCifrado(
        llavero={
            "version": 1,
            "algoritmo": "AES-GCM-256 + PBKDF2-SHA256",
            "iteraciones": ITERACIONES,
            "contenido": {"iv": b64(iv_contenido), "datos": b64(datos_cifrados)},
            "sobres": sobres,
        },
        passwords=passwords,
    )


def leer_json_como_bytes(ruta: Path) -> bytes:
    if not ruta.exists():
        raise FileNotFoundError(f"No encuentro el JSON de entrada: {ruta}")
    datos = ruta.read_bytes()
    try:
        json.loads(datos.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise ValueError("El JSON de entrada debe estar guardado en UTF-8.") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"El fichero de entrada no es JSON valido: {exc}") from exc
    return datos


def escribir_llavero(ruta: Path, llavero: dict) -> None:
    ruta.parent.mkdir(parents=True, exist_ok=True)
    ruta.write_text(
        json.dumps(llavero, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def asegurar_gitignore(root: Path) -> None:
    ruta = root / ".gitignore"
    entrada = FICHERO_PASSWORDS
    contenido = ruta.read_text(encoding="utf-8") if ruta.exists() else ""
    lineas = [line.strip() for line in contenido.splitlines()]
    if entrada in lineas:
        return
    separador = "" if not contenido or contenido.endswith("\n") else "\n"
    ruta.write_text(
        contenido + separador + "\n# Contrasenas generadas para participes (no publicar)\n" + entrada + "\n",
        encoding="utf-8",
    )


def escribir_passwords(root: Path, passwords: list[tuple[str, str]]) -> Path:
    ruta = root / FICHERO_PASSWORDS
    ancho = max(len("Alias"), *(len(alias) for alias, _ in passwords))
    lineas = [
        "CONTRASENAS DE PARTICIPES - NO SUBIR AL REPOSITORIO",
        "",
        "Guarda estas contrasenas en un gestor de contrasenas y elimina este fichero",
        "cuando ya no lo necesites. Si se comprometen, vuelve a cifrar la operacion.",
        "",
        f"{'Alias'.ljust(ancho)}  Contrasena",
        f"{'-' * ancho}  ----------",
    ]
    lineas.extend(f"{alias.ljust(ancho)}  {password}" for alias, password in passwords)
    ruta.write_text("\n".join(lineas) + "\n", encoding="utf-8")
    return ruta


def imprimir_tabla_passwords(passwords: list[tuple[str, str]], ruta: Path) -> None:
    ancho = max(len("Alias"), *(len(alias) for alias, _ in passwords))
    print("\nATENCION: estas contrasenas no deben subirse al repositorio publico.")
    print("Guardalas ahora en un gestor de contrasenas.")
    print(f"Tambien se han escrito en: {ruta}\n")
    print(f"{'Alias'.ljust(ancho)}  Contrasena")
    print(f"{'-' * ancho}  ----------")
    for alias, password in passwords:
        print(f"{alias.ljust(ancho)}  {password}")
    print("")


def confirmar_sobres_invalidos(salida: Path, forzar: bool) -> None:
    if forzar or not salida.exists():
        return
    print(
        f"AVISO: ya existe {salida}. Si continuas, las contrasenas anteriores dejaran de funcionar.",
        file=sys.stderr,
    )
    respuesta = input("Escribe SI para generar un llavero nuevo: ").strip()
    if respuesta != "SI":
        raise SystemExit("Operacion cancelada. No se ha cambiado el llavero.")


def crear_parser() -> argparse.ArgumentParser:
    parser = ParserEspanol(
        description=(
            "Cifra el JSON de una operacion inmobiliaria para publicarlo en una web estatica, "
            "creando un sobre por participe."
        ),
        add_help=False,
    )
    parser._optionals.title = "opciones"
    parser.add_argument("-h", "--help", action="help", help="Muestra esta ayuda y termina.")
    parser.add_argument(
        "--participes",
        help='Aliases separados por comas. Ejemplo: "Xavi,Paco,Antonio,Dani".',
    )
    parser.add_argument(
        "--entrada",
        default="data/tdc/operacion.json",
        help="Ruta del JSON sin cifrar. Por defecto: data/tdc/operacion.json.",
    )
    parser.add_argument(
        "--salida",
        default="data/tdc/llavero.json",
        help="Ruta donde se escribira el llavero cifrado. Por defecto: data/tdc/llavero.json.",
    )
    parser.add_argument(
        "--forzar",
        action="store_true",
        help="Sobrescribe un llavero existente sin pedir confirmacion.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = crear_parser()
    args = parser.parse_args(argv)
    root = repo_root()
    entrada = (root / args.entrada).resolve() if not Path(args.entrada).is_absolute() else Path(args.entrada)
    salida = (root / args.salida).resolve() if not Path(args.salida).is_absolute() else Path(args.salida)

    try:
        if not args.participes:
            parser.error("faltan argumentos obligatorios: --participes")
        participes = parsear_participes(args.participes)
        confirmar_sobres_invalidos(salida, args.forzar)
        datos_json = leer_json_como_bytes(entrada)
        resultado = cifrar_operacion_bytes(datos_json, participes)
        escribir_llavero(salida, resultado.llavero)
        asegurar_gitignore(root)
        ruta_passwords = escribir_passwords(root, resultado.passwords)
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print(f"Llavero cifrado escrito en: {salida}")
    print(f"Entropia estimada por contrasena: {entropia_password():.1f} bits")
    imprimir_tabla_passwords(resultado.passwords, ruta_passwords)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
