import argparse
import re
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

from colorama import Fore, Style, init
from fpdf import FPDF

from modules.header_check import check_security_headers
from modules.port_scanner import scan_ports
from modules.ssl_check import check_ssl_expiry


init(autoreset=True)

BASE_DIR = Path(__file__).resolve().parent
REPORTS_DIR = BASE_DIR / "reports"


def normalizar_destino(valor):
    """Separa el servidor de la URL que se analizará."""
    valor = valor.strip()

    if not valor:
        raise ValueError("Debes indicar un dominio o una URL.")

    if any(caracter.isspace() for caracter in valor):
        raise ValueError(
            "La dirección contiene espacios. Usa %20 si forman parte de la ruta."
        )

    if valor.startswith("//"):
        valor = "https:" + valor
    elif "://" not in valor:
        valor = "https://" + valor

    partes = urlsplit(valor)

    if partes.scheme not in {"http", "https"}:
        raise ValueError("Solo se admiten URLs HTTP o HTTPS.")

    if not partes.hostname:
        raise ValueError("La dirección no contiene un servidor válido.")

    if partes.username is not None or partes.password is not None:
        raise ValueError("No incluyas usuarios ni contraseñas en la URL.")

    # Los módulos existentes reciben solo un servidor.
    # No se admiten puertos alternativos sin adaptar esos módulos.
    puerto_estandar = 443 if partes.scheme == "https" else 80

    if partes.port not in {None, puerto_estandar}:
        raise ValueError(
            "Los puertos alternativos requieren adaptar port_scanner.py "
            "y ssl_check.py. Utiliza HTTP en 80 o HTTPS en 443."
        )

    host = partes.hostname

    # Conserva ruta y parámetros; elimina el fragmento #seccion,
    # que no se envía al servidor.
    url = partes._replace(
        path=partes.path or "/",
        fragment="",
    ).geturl()

    return host, url


def texto_pdf(valor):
    """
    Las fuentes básicas de FPDF no admiten todos los caracteres Unicode.
    Sustituye caracteres incompatibles para evitar que falle el informe.
    """
    return str(valor).encode("latin-1", errors="replace").decode("latin-1")


def generate_pdf_report(
    url,
    host,
    ports,
    port_error,
    http_info,
    ssl_info,
):
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    def linea(texto, negrita=False, tamano=10):
        pdf.set_font("Arial", "B" if negrita else "", tamano)
        pdf.set_x(pdf.l_margin)
        pdf.multi_cell(0, 7, texto_pdf(texto))
        pdf.set_x(pdf.l_margin)

    def seccion(titulo):
        pdf.ln(5)
        linea(titulo, negrita=True, tamano=12)

    linea("Security Scan Report", negrita=True, tamano=16)
    linea(f"URL solicitada: {url}")
    linea(f"Servidor para puertos y TLS: {host}")
    linea(f"Fecha: {datetime.now().astimezone().isoformat(timespec='seconds')}")

    seccion("1. Puertos abiertos")

    if port_error:
        linea(f"No evaluado: {port_error}")
    elif ports:
        linea(f"Puertos encontrados: {', '.join(map(str, ports))}")
    else:
        linea("No se encontraron puertos abiertos entre los comprobados.")

    linea("El resultado depende del alcance del módulo port_scanner.py.")

    seccion("2. Cabeceras de seguridad HTTP")

    if http_info["error"]:
        linea(f"No evaluado: {http_info['error']}")
    else:
        linea(f"URL final: {http_info['final_url']}")
        linea(f"Estado HTTP: {http_info['status_code']}")

        if http_info["redirects"]:
            linea("Redirecciones:", negrita=True)

            for salto in http_info["redirects"]:
                linea(
                    f"{salto['status_code']} | {salto['url']} "
                    f"| Location: {salto['location']}"
                )

        for aviso in http_info["warnings"]:
            linea(f"AVISO: {aviso}")

        for cabecera, valor in http_info["headers"].items():
            linea(f"{cabecera}: {valor}")

        linea(
            "MISSING indica ausencia. La presencia de una cabecera "
            "no garantiza que su configuración sea adecuada."
        )

    seccion("3. Certificado TLS del servidor original")

    if ssl_info.get("error"):
        linea(f"No evaluado: {ssl_info['error']}")
    else:
        linea(f"Emisor: {ssl_info.get('issuer', 'No disponible')}")
        linea(
            "Días para expirar: "
            f"{ssl_info.get('days_to_expire', 'No disponible')}"
        )

    linea(
        "Esta sección utiliza ssl_check.py; no implica una auditoría "
        "completa de protocolos, cifrados o configuración TLS."
    )

    nombre_seguro = re.sub(r"[^A-Za-z0-9._-]", "_", host)
    fecha = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    filename = REPORTS_DIR / f"scan_{nombre_seguro}_{fecha}.pdf"

    pdf.output(str(filename))
    return filename


def main():
    parser = argparse.ArgumentParser(
        description="VulnShield Scanner - Auditor básico de seguridad"
    )
    parser.add_argument(
        "-t",
        "--target",
        required=True,
        help=(
            "Dominio o URL completa. "
            "Ejemplo: https://labancestral.cl/noticias/"
        ),
    )
    args = parser.parse_args()

    try:
        host, url = normalizar_destino(args.target)
    except ValueError as error:
        parser.error(str(error))

    print(
        f"\n{Fore.CYAN}--- Iniciando escaneo: {url} ---"
        f"{Style.RESET_ALL}\n"
    )
    print(f"Servidor para puertos y TLS: {host}")

    # 1. Puertos del servidor original.
    print(f"\n{Fore.YELLOW}[*] Escaneando puertos comunes...")

    ports = []
    port_error = None

    try:
        ports = list(scan_ports(host))
        if ports:
            print(f"    Puertos abiertos: {Fore.GREEN}{ports}")
        else:
            print("    No se encontraron puertos abiertos en el alcance probado.")
    except Exception as error:
        # Aísla fallos del módulo para poder continuar el informe.
        port_error = f"{type(error).__name__}: {error}"
        print(f"    {Fore.RED}No se pudo completar: {port_error}")

    # 2. Cabeceras de la URL solicitada y su respuesta final.
    print(f"\n{Fore.YELLOW}[*] Analizando cabeceras HTTP...")
    http_info = check_security_headers(url)

    if http_info["error"]:
        print(f"    {Fore.RED}No evaluado: {http_info['error']}")
    else:
        print(f"    URL final: {http_info['final_url']}")
        print(f"    Estado HTTP: {http_info['status_code']}")

        for salto in http_info["redirects"]:
            print(
                f"    Redirección {salto['status_code']}: "
                f"{salto['url']} -> {salto['location']}"
            )

        for aviso in http_info["warnings"]:
            print(f"    {Fore.YELLOW}AVISO: {aviso}")

        for cabecera, valor in http_info["headers"].items():
            # Presente no equivale a seguro: evitamos marcarlo como aprobado.
            color = Fore.RED if valor == "MISSING" else Fore.CYAN
            print(f"    {cabecera}: {color}{valor}")

    # 3. TLS del servidor original, no de un destino de redirección.
    print(f"\n{Fore.YELLOW}[*] Verificando certificado TLS de {host}...")

    if urlsplit(url).scheme != "https":
        ssl_info = {
            "error": (
                "La URL original utiliza HTTP. "
                "Ejecuta también el análisis con su URL HTTPS."
            )
        }
    else:
        try:
            ssl_info = check_ssl_expiry(host)
        except Exception as error:
            ssl_info = {
                "error": f"{type(error).__name__}: {error}"
            }

    if ssl_info.get("error"):
        print(f"    {Fore.RED}No evaluado: {ssl_info['error']}")
    else:
        print(f"    Emisor: {ssl_info.get('issuer', 'No disponible')}")
        print(
            "    Días para expirar: "
            f"{ssl_info.get('days_to_expire', 'No disponible')}"
        )

    # 4. Informe.
    print(f"\n{Fore.YELLOW}[*] Generando reporte PDF...")

    report_path = generate_pdf_report(
        url=url,
        host=host,
        ports=ports,
        port_error=port_error,
        http_info=http_info,
        ssl_info=ssl_info,
    )

    print(f"\n{Fore.CYAN}--- Escaneo finalizado ---")
    print(f"{Fore.BLUE}[i] Reporte guardado en: {report_path}")


if __name__ == "__main__":
    main()