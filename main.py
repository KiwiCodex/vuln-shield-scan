import argparse
import os  # Necesario para manejar carpetas
from fpdf import FPDF  # Librería para generar el PDF
from datetime import datetime
from colorama import Fore, Style, init
from modules.header_check import check_security_headers
from modules.port_scanner import scan_ports
from modules.ssl_check import check_ssl_expiry

# Se inicializa colorama para ver colores en la terminal
init(autoreset=True)

def generate_pdf_report(target, ports, headers, ssl_info):

    # 1. Se asegura de que la carpeta existe
    if not os.path.exists("reports"):
        os.makedirs("reports")

    pdf = FPDF()
    pdf.add_page()
    
    # Título del Reporte
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(200, 10, txt=f"Security Scan Report: {target}", ln=True, align='C')
    pdf.set_font("Arial", size=10)
    pdf.cell(200, 10, txt=f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align='C')
    pdf.ln(10) # Salto de línea

    # Sección de Puertos
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(200, 10, txt="1. Open Ports Scan", ln=True)
    pdf.set_font("Arial", size=10)
    pdf.cell(200, 10, txt=f"Ports found: {', '.join(map(str, ports)) if ports else 'None'}", ln=True)
    pdf.ln(5)

    # Sección de Headers
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(200, 10, txt="2. HTTP Security Headers", ln=True)
    pdf.set_font("Arial", size=10)
    for header, status in headers.items():
        pdf.cell(200, 8, txt=f"{header}: {status}", ln=True)
    pdf.ln(5)

    # Sección de SSL
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(200, 10, txt="3. SSL/TLS Status", ln=True)
    pdf.set_font("Arial", size=10)
    if "error" in ssl_info:
        pdf.cell(200, 10, txt=f"Error: {ssl_info['error']}", ln=True)
    else:
        pdf.cell(200, 8, txt=f"Issuer: {ssl_info['issuer']}", ln=True)
        pdf.cell(200, 8, txt=f"Days to Expire: {ssl_info['days_to_expire']}", ln=True)

    # 2. Guardar el archivo con nombre dinámico
    filename = f"reports/scan_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    pdf.output(filename)
    return filename


def main():
    # Se configuran los argumentos de línea de comandos
    parser = argparse.ArgumentParser(description="VulnShield Scanner - Basic Security Auditor")
    parser.add_argument("-t", "--target", help="Dominio o IP a escanear (ej: google.com)", required=True)
    args = parser.parse_args()

    target = args.target

    print(f"\n{Fore.CYAN}--- Iniciando Escaneo en: {target} ---{Style.RESET_ALL}\n")

    # 1. Escaneo de Puertos
    print(f"{Fore.YELLOW}[*] Escaneando puertos comunes...")
    ports = scan_ports(target)
    print(f"    Puertos abiertos: {Fore.GREEN}{ports if ports else 'Ninguno'}")

    # 2. Análisis de Headers (Agregamos http:// para requests)
    url = f"https://{target}"
    print(f"\n{Fore.YELLOW}[*] Analizando cabeceras de seguridad HTTP...")
    headers = check_security_headers(url)
    for header, status in headers.items():
        color = Fore.GREEN if status != "MISSING" else Fore.RED
        print(f"    {header}: {color}{status}")

    # 3. Verificación de SSL
    print(f"\n{Fore.YELLOW}[*] Verificando certificado SSL...")
    ssl_info = check_ssl_expiry(target)
    if "error" in ssl_info:
        print(f"    {Fore.RED}Error: {ssl_info['error']}")
    else:
        print(f"    Emisor: {ssl_info['issuer']}")
        print(f"    Días para expirar: {ssl_info['days_to_expire']}")
    
    # --- Generación del Reporte ---
    print(f"\n{Fore.YELLOW}[*] Generando reporte PDF...")
    report_path = generate_pdf_report(target, ports, headers, ssl_info)

    print(f"\n{Fore.CYAN}--- Escaneo Finalizado ---{Style.RESET_ALL}")
    print(f"{Fore.BLUE}[i] Reporte guardado en: {report_path}")

if __name__ == "__main__":
    main()