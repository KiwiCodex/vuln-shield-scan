import math
import socket
import ssl
from datetime import datetime, timezone


def obtener_emisor(certificado):
    """Obtiene el nombre del emisor sin asumir que existe commonName."""
    atributos = {}

    for grupo in certificado.get("issuer", ()):
        for clave, valor in grupo:
            atributos.setdefault(clave, []).append(valor)

    for campo in ("commonName", "organizationName"):
        if atributos.get(campo):
            return ", ".join(atributos[campo])

    return "No disponible"


def check_ssl_expiry(hostname, port=443, timeout=5):
    """
    Valida el certificado del servidor y calcula su caducidad en UTC.

    hostname debe contener solo el dominio o IP, sin esquema ni ruta.

    Comprueba una conexión TLS. No enumera todos los protocolos,
    cifrados ni certificados de todas las IP del dominio.
    """
    try:
        context = ssl.create_default_context()

        with socket.create_connection(
            (hostname, port),
            timeout=timeout,
        ) as sock:
            with context.wrap_socket(
                sock,
                server_hostname=hostname,
            ) as tls_socket:
                certificado = tls_socket.getpeercert()
                version_tls = tls_socket.version()
                cifrado = tls_socket.cipher()
                ip_remota = tls_socket.getpeername()[0]

        fecha_texto = certificado.get("notAfter")

        if not fecha_texto:
            return {
                "error": "El certificado no incluye una fecha de expiración.",
                "status": "UNKNOWN",
            }

        # Interpreta la fecha del certificado como UTC, sin depender
        # del idioma ni de la zona horaria local del equipo.
        fecha_expiracion = datetime.fromtimestamp(
            ssl.cert_time_to_seconds(fecha_texto),
            tz=timezone.utc,
        )

        ahora = datetime.now(timezone.utc)
        segundos_restantes = (fecha_expiracion - ahora).total_seconds()
        dias_restantes = math.floor(segundos_restantes / 86400)

        # Umbrales operativos de aviso; no son una medida completa
        # de la seguridad de TLS.
        if segundos_restantes <= 0:
            estado = "CRITICAL"
        elif segundos_restantes <= 30 * 86400:
            estado = "WARNING"
        else:
            estado = "OK"

        return {
            "issuer": obtener_emisor(certificado),
            "days_to_expire": dias_restantes,
            "expires_at": fecha_expiracion.isoformat(),
            "status": estado,
            "tls_version": version_tls,
            "cipher": cifrado[0] if cifrado else None,
            "remote_ip": ip_remota,
            "port": port,
        }

    except ssl.SSLCertVerificationError as error:
        return {
            "error": (
                "No se pudo validar el certificado con la configuración "
                f"de confianza de este equipo: {error.verify_message}"
            ),
            "status": "CRITICAL",
        }

    except ssl.SSLError as error:
        return {
            "error": f"No se pudo negociar la conexión TLS: {error}",
            "status": "UNKNOWN",
        }

    except socket.gaierror as error:
        return {
            "error": f"No se pudo resolver el servidor: {error}",
            "status": "UNKNOWN",
        }

    except (TimeoutError, socket.timeout):
        return {
            "error": "Se agotó el tiempo de conexión o negociación TLS.",
            "status": "UNKNOWN",
        }

    except OSError as error:
        return {
            "error": f"Error de conexión: {error}",
            "status": "UNKNOWN",
        }

    except (ValueError, OverflowError) as error:
        return {
            "error": f"No se pudo interpretar la fecha del certificado: {error}",
            "status": "UNKNOWN",
        }