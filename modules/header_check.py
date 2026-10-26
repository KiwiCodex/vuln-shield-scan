from urllib.parse import urlsplit

import requests


HEADERS_TO_CHECK = (
    "Content-Security-Policy",  # CSP: Solo acepta scripts y fotos que vengan de estos sitios de confianza, evitando ataques XSS
    "Strict-Transport-Security", # HSTS: Obliga al navegador a usar siempre HTTPS (conexión cifrada) en lugar de HTTP (texto plano). Evita que alguien "escuche" la comunicación en redes públicas.
    "X-Frame-Options", # Sirve para evitar el Clickjacking, donde un atacante pone un botón invisible sobre tu página para engañar al usuario y que haga clic en algo que no quería.
    "X-Content-Type-Options", # Evita el MIME-sniffing. Obliga al navegador a respetar el tipo de archivo que el servidor declara
)


def check_security_headers(url):
    """
    Consulta una URL y analiza las cabeceras de la respuesta final.

    Sigue redirecciones HTTP, registra el recorrido y mantiene
    activa la verificación del certificado HTTPS.

    Un fallo de conexión no se presenta como cabeceras ausentes.
    """
    resultado = {
        "requested_url": url,
        "final_url": None,
        "status_code": None,
        "redirects": [],
        "headers": {},
        "warnings": [],
        "error": None,
    }

    try:
        with requests.Session() as session:
            session.max_redirects = 10
            session.headers.update({
                "User-Agent": "VulnShield/1.0",
            })

            # Timeout de conexión y de lectura, respectivamente.
            # No representa un límite total de duración del análisis.
            with session.get(
                url,
                timeout=(5, 10),
                allow_redirects=True,
                verify=True,
                stream=True,
            ) as response:
                resultado["final_url"] = response.url
                resultado["status_code"] = response.status_code

                resultado["redirects"] = [
                    {
                        "status_code": salto.status_code,
                        "url": salto.url,
                        "location": salto.headers.get("Location", ""),
                    }
                    for salto in response.history
                ]

                for cabecera in HEADERS_TO_CHECK:
                    valor = response.headers.get(cabecera)
                    resultado["headers"][cabecera] = (
                        valor.strip()
                        if valor and valor.strip()
                        else "MISSING"
                    )

                # No usamos raise_for_status(): las respuestas de error
                # también tienen cabeceras, pero deben identificarse.
                if response.status_code >= 400:
                    resultado["warnings"].append(
                        f"El servidor respondió HTTP {response.status_code}. "
                        "Las cabeceras pertenecen a esa respuesta de error, "
                        "no necesariamente a la página esperada."
                    )
                elif not 200 <= response.status_code < 300:
                    resultado["warnings"].append(
                        f"La respuesta final es HTTP {response.status_code}; "
                        "no es una respuesta 2xx."
                    )

                original = urlsplit(url)
                final = urlsplit(response.url)

                if original.hostname != final.hostname:
                    resultado["warnings"].append(
                        "La redirección terminó en otro servidor. "
                        "Estas cabeceras corresponden al destino final; "
                        "el escaneo de puertos y TLS utiliza el servidor original."
                    )

                if final.scheme != "https":
                    resultado["warnings"].append(
                        "La respuesta final utiliza HTTP. "
                        "HSTS solo tiene efecto cuando se recibe mediante HTTPS."
                    )

                recorrido = [
                    salto.url for salto in response.history
                ] + [response.url]

                if any(
                    urlsplit(anterior).scheme == "https"
                    and urlsplit(siguiente).scheme == "http"
                    for anterior, siguiente in zip(
                        recorrido,
                        recorrido[1:],
                    )
                ):
                    resultado["warnings"].append(
                        "Se detectó una redirección de HTTPS a HTTP."
                    )

                csp_report_only = response.headers.get(
                    "Content-Security-Policy-Report-Only"
                )
                if csp_report_only:
                    resultado["warnings"].append(
                        "Existe Content-Security-Policy-Report-Only. "
                        "Esta política informa de infracciones, "
                        "pero no las bloquea."
                    )

    except requests.exceptions.SSLError as error:
        resultado["error"] = (
            "Falló la conexión TLS o la validación del certificado: "
            f"{error}"
        )
    except requests.exceptions.Timeout as error:
        resultado["error"] = (
            f"Se agotó el tiempo de conexión o lectura: {error}"
        )
    except requests.exceptions.TooManyRedirects:
        resultado["error"] = (
            "Se superó el límite de 10 redirecciones. "
            "Puede existir un bucle de redirecciones."
        )
    except requests.exceptions.ConnectionError as error:
        resultado["error"] = (
            f"No se pudo conectar con el servidor: {error}"
        )
    except requests.exceptions.RequestException as error:
        resultado["error"] = (
            f"No se pudo completar la solicitud HTTP: {error}"
        )

    return resultado