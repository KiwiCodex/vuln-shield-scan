import ssl
import socket
from datetime import datetime 

def check_ssl_expiry(hostname):
    # Verifica la validez de los certificados SSL/TLS

    context = ssl.create_default_context()

    try:
        # Se estable una conexión segura para obtener metadatos del certificado

        with socket.create_connection((hostname, 443), timeout = 5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

                # Se extrae la fecha de expiración
                expire_date_str = cert['notAfter']
                if not expire_date_str:
                    return {"error": "No se pudo obtener la fecha de expiración", "status": "UNKNOWN"}
                expire_date = datetime.strptime(expire_date_str, '%b %d %H:%M:%S %Y %Z')

                days_to_expire = (expire_date - datetime.now()).days

                return {
                    "issuer": dict(x[0] for x in cert['issuer'])['commonName'],
                    "days_to_expire": days_to_expire,
                    "status": "Ok" if days_to_expire > 30 else "WARNING"
                }
    except Exception as e:
        return {"error": str(e), "status": "CRITICAL"}

