import socket
import argparse
import nmap
from concurrent.futures import ThreadPoolExecutor
from pyfiglet import Figlet

f = Figlet(font='slant')
print(f.renderText('Portscan'))

def grab_banner(host, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            s.connect((host, port))
            s.sendall(b'HEAD / HTTP/1.1\r\n\r\n')
            banner = s.recv(1024).decode().strip()
            return banner
    except Exception as e:
        return None

def scan_port(host, port):
    try:
        nm = nmap.PortScanner()
        nm.scan(host, str(port))
        info_servico = nm[host]['tcp'][port]
        banner = grab_banner(host, port)
        return {
            "estado": info_servico['state'],
            "serviço": info_servico['name'],
            "versão": info_servico.get('version', 'desconhecida'),
            "banner": banner
        }
    except Exception as e:
        return None

def scan_ports(host, ports):
    resultados = {}
    with ThreadPoolExecutor(max_workers=100) as executor:
        future_to_port = {executor.submit(scan_port, host, port): port for port in ports}
        for future in future_to_port:
            port = future_to_port[future]
            result = future.result()
            if result and result["estado"] == "open":
                resultados[port] = result
    return resultados

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scanner de Portas com Captura de Banners e Detecção de Serviços")
    parser.add_argument("host", help="Host para escanear")
    parser.add_argument("-p", "--ports", nargs="+", type=int, help="Lista de portas para escanear", required=True)
    args = parser.parse_args()

    host = args.host
    ports = args.ports

    print(f"Escanenado {host} nas portas {ports}")
    resultados = scan_ports(host, ports)

    if resultados:
        print(f"Relatório de scan de Portscan para {host}")
        print(f"Host está online.")
        for porta, info in resultados.items():
            print(f"{porta}/tcp aberta  {info['serviço']} {info['versão']}")
            if info['banner']:
                print(f"Banner: {info['banner']}")
    else:
        print("Nenhuma porta aberta encontrada.")
