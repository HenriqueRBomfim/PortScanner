import socket
import argparse
import threading
import tkinter as tk
from tkinter import scrolledtext
from queue import Queue
import nmap  # Importando a biblioteca nmap

def log_result(queue):
    """Atualiza a interface gráfica com os resultados do scan a partir de uma fila."""
    while not queue.empty():
        message = queue.get()
        result_text.insert(tk.END, message + "\n")
        result_text.see(tk.END)

def get_banner(s, port):
    """Captura o banner do serviço TCP após a conexão ser estabelecida."""
    try:
        # Comandos comuns para serviços diferentes
        if port == 80:  # HTTP
            s.sendall(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        elif port == 21:  # FTP
            s.sendall(b"USER anonymous\r\n")
        elif port == 23:  # Telnet
            s.sendall(b"\r\n")
        else:
            s.sendall(b"HELLO\r\n")
        
        # Recebe o banner do serviço
        banner = s.recv(1024).decode().strip()
        
        # Caso o banner seja muito grande ou dividido em pacotes, tenta ler mais
        if len(banner) < 1024:
            s.settimeout(2)
            additional_data = s.recv(1024).decode().strip()
            banner += additional_data
        
        return banner
    except Exception as e:
        return None

def identify_os_from_nmap(target):
    """Tenta identificar o sistema operacional usando Nmap"""
    nm = nmap.PortScanner()
    try:
        nm.scan(target, '1-1024', arguments='-O')  # -O para tentar detectar o sistema operacional
        if 'osmatch' in nm[target]:
            return nm[target]['osmatch'][0]['name']
        else:
            return "Sistema operacional não detectado"
    except Exception as e:
        return f"Erro ao tentar detectar o sistema operacional: {str(e)}"

def scan_tcp(target, port, ipv6=False, queue=None):
    """Função que realiza o escaneamento de uma porta TCP e tenta identificar o sistema operacional via banner e Nmap."""
    try:
        family = socket.AF_INET6 if ipv6 else socket.AF_INET
        s = socket.socket(family, socket.SOCK_STREAM)
        s.settimeout(1)
        result = s.connect_ex((target, port))
        
        if result == 0:  # Conexão bem-sucedida (porta aberta)
            banner = get_banner(s, port)  # Captura o banner do serviço
            os_info = identify_os_from_nmap(target)  # Detecta o sistema operacional via Nmap
            message = f"[+] Porta {port} aberta - {get_service_name(port)} | Sistema Operacional: {os_info}"
        elif result == 111 or result == 10061:  # Porta fechada (Linux ou Windows)
            message = f"[-] Porta {port} fechada"
        else:
            message = f"[?] Porta {port} filtrada ou com erro desconhecido"
        
        queue.put(message)
        s.close()
    except Exception as e:
        queue.put(f"Erro ao escanear porta {port}: {e}")

def scan_udp(target, port, ipv6=False, queue=None):
    try:
        family = socket.AF_INET6 if ipv6 else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.sendto(b"", (target, port))
        sock.settimeout(2)
        try:
            data, _ = sock.recvfrom(1024)
            queue.put(f"[+] Porta UDP {port} pode estar aberta")
        except socket.timeout:
            queue.put(f"[-] Sem resposta na porta UDP {port}")
        sock.close()
    except Exception as e:
        queue.put(f"Erro ao escanear porta UDP {port}: {e}")

def get_service_name(port):
    try:
        return socket.getservbyport(port)
    except:
        return "Desconhecido"

def run_scan():
    target = target_entry.get()
    port_range = ports_entry.get()
    start_port, end_port = map(int, port_range.split("-"))
    ipv6 = ipv6_var.get()
    udp = udp_var.get()
    
    result_text.delete(1.0, tk.END)
    queue = Queue()
    
    threads = []
    for port in range(start_port, end_port + 1):
        if udp:
            t = threading.Thread(target=scan_udp, args=(target, port, ipv6, queue))
        else:
            t = threading.Thread(target=scan_tcp, args=(target, port, ipv6, queue))
        threads.append(t)
        t.start()
    
    for t in threads:
        t.join()
    
    # Atualiza a interface gráfica com os resultados da fila
    log_result(queue)

def create_gui():
    global target_entry, ports_entry, ipv6_var, udp_var, result_text
    
    root = tk.Tk()
    root.title("Scanner de Portas")
    
    tk.Label(root, text="Alvo:").grid(row=0, column=0)
    target_entry = tk.Entry(root)
    target_entry.grid(row=0, column=1)
    
    tk.Label(root, text="Intervalo de Portas:").grid(row=1, column=0)
    ports_entry = tk.Entry(root)
    ports_entry.grid(row=1, column=1)
    ports_entry.insert(0, "1-1024")
    
    ipv6_var = tk.BooleanVar()
    tk.Checkbutton(root, text="IPv6", variable=ipv6_var).grid(row=2, column=0)
    
    udp_var = tk.BooleanVar()
    tk.Checkbutton(root, text="UDP", variable=udp_var).grid(row=2, column=1)
    
    tk.Button(root, text="Iniciar Scan", command=lambda: threading.Thread(target=run_scan).start()).grid(row=3, columnspan=2)

    result_text = scrolledtext.ScrolledText(root, height=15, width=50)
    result_text.grid(row=4, column=0, columnspan=2, padx=5, pady=5)
    
    root.mainloop()

def main():
    parser = argparse.ArgumentParser(description="Scanner de Portas TCP e UDP")
    parser.add_argument("target", nargs="?", help="IP ou hostname do alvo")
    parser.add_argument("-p", "--ports", type=str, help="Intervalo de portas, ex: 20-100")
    parser.add_argument("--udp", action="store_true", help="Habilita o escaneamento UDP")
    parser.add_argument("--ipv6", action="store_true", help="Habilita suporte a IPv6")
    args = parser.parse_args()

    if args.target:
        # Modo de linha de comando (sem GUI)
        target = args.target
        port_range = args.ports if args.ports else "1-1024"
        start_port, end_port = map(int, port_range.split("-"))
        
        queue = Queue()
        threads = []
        for port in range(start_port, end_port + 1):
            if args.udp:
                t = threading.Thread(target=scan_udp, args=(target, port, args.ipv6, queue))
            else:
                t = threading.Thread(target=scan_tcp, args=(target, port, args.ipv6, queue))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        # Imprime os resultados diretamente no terminal (modo CLI)
        while not queue.empty():
            print(queue.get())

    else:
        create_gui()

if __name__ == "__main__":
    main()
