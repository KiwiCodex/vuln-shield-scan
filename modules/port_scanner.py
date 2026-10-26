import errno
import socket
import warnings


# Alcance explícito del escaneo.
# Un puerto abierto no identifica por sí solo el servicio que lo utiliza.
COMMON_PORTS = (
    21,    # Habitualmente FTP
    22,    # Habitualmente SSH
    80,    # Habitualmente HTTP
    443,   # Habitualmente HTTPS
    5432,  # Habitualmente PostgreSQL
    8080,  # Habitualmente HTTP alternativo
)


def scan_ports(host, ports=None, timeout=1):
    """
    Realiza conexiones TCP a los puertos indicados.

    Devuelve una lista ordenada de puertos que aceptaron conexiones
    en al menos una de las direcciones IPv4/IPv6 resueltas.

    Los resultados no distinguen servicios ni versiones.
    Los fallos DNS se propagan al main.py.
    Los resultados inconclusos generan un aviso.
    """
    if timeout <= 0:
        raise ValueError("El timeout debe ser mayor que cero.")

    if ports is None:
        ports = COMMON_PORTS

    puertos = sorted(set(ports))

    for puerto in puertos:
        if (
            not isinstance(puerto, int)
            or isinstance(puerto, bool)
            or not 1 <= puerto <= 65535
        ):
            raise ValueError(f"Puerto inválido: {puerto!r}")

    # AF_UNSPEC permite que el sistema devuelva IPv4 e IPv6.
    # El puerto 0 sirve aquí para resolver direcciones; no se escanea.
    resultados_dns = socket.getaddrinfo(
        host,
        0,
        family=socket.AF_UNSPEC,
        type=socket.SOCK_STREAM,
        proto=socket.IPPROTO_TCP,
    )

    direcciones = []
    vistas = set()

    for familia, tipo, protocolo, _, direccion in resultados_dns:
        clave = (familia, tipo, protocolo, direccion)

        if clave not in vistas:
            vistas.add(clave)
            direcciones.append(
                (familia, tipo, protocolo, direccion)
            )

    if not direcciones:
        raise OSError("No se encontraron direcciones TCP para el servidor.")

    puertos_abiertos = set()
    inconclusos = []

    # Valores habituales de conexión rechazada en Unix y Windows.
    codigos_rechazo = {
        errno.ECONNREFUSED,
        10061,
    }

    for familia, tipo, protocolo, direccion in direcciones:
        ip = direccion[0]

        for puerto in puertos:
            if familia == socket.AF_INET6:
                destino = (
                    ip,
                    puerto,
                    direccion[2],  # flowinfo
                    direccion[3],  # scope_id
                )
            else:
                destino = (ip, puerto)

            try:
                with socket.socket(
                    familia,
                    tipo,
                    protocolo,
                ) as conexion:
                    conexion.settimeout(timeout)
                    codigo = conexion.connect_ex(destino)

                if codigo == 0:
                    puertos_abiertos.add(puerto)

                elif codigo not in codigos_rechazo:
                    # Timeout, falta de ruta, filtrado u otro error.
                    # No se interpreta automáticamente como cerrado.
                    inconclusos.append(
                        f"{ip}, puerto {puerto}, código {codigo}"
                    )

            except OSError as error:
                inconclusos.append(
                    f"{ip}, puerto {puerto}: {error}"
                )

    if inconclusos:
        ejemplos = "; ".join(inconclusos[:3])

        warnings.warn(
            f"{len(inconclusos)} comprobaciones TCP fueron inconclusas. "
            "Los puertos ausentes de la lista no deben interpretarse "
            f"todos como cerrados. Ejemplos: {ejemplos}",
            RuntimeWarning,
            stacklevel=2,
        )

    return sorted(puertos_abiertos)