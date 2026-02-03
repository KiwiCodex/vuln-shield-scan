import socket

def scan_ports(host):
    # Definimos los puertos 'well-known' que representan servicios críticos
    # 21: FTP, 22: SSH, 80: HTTP, 443: HTTPS, 8080: HTTP-Alt
    common_ports = [21, 22, 80, 443, 8080]

    open_ports = []
    for port in common_ports:
        # Creamos un socket usando la familia IPv4 (AF_INET) 
        # y el protocolo de transporte orientado a conexión TCP (SOCK_STREAM)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        if s.connect_ex((host, port)) == 0:
            open_ports.append(port)
        s.close()
    return open_ports