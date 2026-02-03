import requests

def check_security_headers(url):
    headers_to_check = [
        "Content-Security-Policy",   # CSP: Solo acepta scripts y fotos que vengan de estos sitios de confianza, evitando ataques XSS
        "Strict-Transport-Security", # HSTS: Obliga al navegador a usar siempre HTTPS (conexión cifrada) en lugar de HTTP (texto plano). Evita que alguien "escuche" la comunicación en redes públicas.
        "X-Frame-Options",           # Sirve para evitar el Clickjacking, donde un atacante pone un botón invisible sobre tu página para engañar al usuario y que haga clic en algo que no quería.
        "X-Content-Type-Options"     # Evita el MIME-sniffing. Obliga al navegador a respetar el tipo de archivo que el servidor declara
    ]
    try: 
        response = requests.get(url, timeout=5)
        results = {}
        for header in headers_to_check:
            results[header] = response.headers.get(header, "MISSING")
        return results
    except Exception as e:
        return {"error": str(e)}