import socket
import threading
import time
import select
import sys
import datetime
import os 

# ==============================================================================
#  CONFIGURAÇÕES VISUAIS (UI/UX)
# ==============================================================================

RESET   = "\033[0m"
BOLD    = "\033[1m"
GREEN   = "\033[92m"   # Você
CYAN    = "\033[96m"   # Amigo
YELLOW  = "\033[93m"   # Sistema
GRAY    = "\033[90m"   # Hora
RED     = "\033[91m"   # Erro
CL_LINE = "\033[K"     # Limpa a linha
UP_LINE = "\033[F"     # Sobe o cursor

# --- VARIÁVEIS GLOBAIS ---
MY_NICK = "Eu"
PEER_NICK = "Desconhecido"
RUNNING = True  # Controle do Loop

# --- REDE ---
MAPA_BITS = {'00': 0, '01': 1, '10': 2, '11': 3}
MAPA_PORTAS = {v: k for k, v in MAPA_BITS.items()}

def get_time():
    return datetime.datetime.now().strftime("%H:%M")

# ==============================================================================
#  INTERFACE
# ==============================================================================

def print_header(ip_destino, minha_base, destino_base):
    os.system('cls' if os.name == 'nt' else 'clear')
    print(f"{YELLOW}╔════════════════════════════════════════════════════╗{RESET}")
    print(f"{YELLOW}║          PHANTOM CHAT - SECURE CHANNEL             ║{RESET}")
    print(f"{YELLOW}╚════════════════════════════════════════════════════╝{RESET}")
    print(f" 👤 {BOLD}Eu sou:{RESET} {GREEN}{MY_NICK}{RESET}")
    print(f" 🎧 {BOLD}Escutando em:{RESET} Portas {minha_base} até {minha_base+3}")
    print(f" 🗣️ {BOLD}Falando para:{RESET} {CYAN}{PEER_NICK}{RESET} ({ip_destino}:{destino_base}+)")
    print(f" 🛠️ {BOLD}Comandos:{RESET} /cls, /nick, /quit")
    print(f"{GRAY}------------------------------------------------------{RESET}\n")
    sys.stdout.write(f"{GREEN}{MY_NICK}:{RESET} ")
    sys.stdout.flush()

def print_msg_sistema(msg, tipo="INFO"):
    cor = YELLOW if tipo == "INFO" else RED
    sys.stdout.write(f"\r{CL_LINE}{GRAY}[SYSTEM] {cor}⚡ {msg}{RESET}\n{GREEN}{MY_NICK}:{RESET} ")
    sys.stdout.flush()

def print_msg_recebida(msg):
    sys.stdout.write(f"\r{CL_LINE}\a{GRAY}[{get_time()}] {CYAN}{BOLD}{PEER_NICK}:{RESET} {msg}\n{GREEN}{MY_NICK}:{RESET} ")
    sys.stdout.flush()

def print_msg_enviada(msg):
    sys.stdout.write(f"{UP_LINE}{CL_LINE}\r{GRAY}[{get_time()}] {GREEN}{BOLD}{MY_NICK}:{RESET} {msg}\n{GREEN}{MY_NICK}:{RESET} ")
    sys.stdout.flush()

# ==============================================================================
#  REDE
# ==============================================================================

def text_to_bits(text):
    try:
        bits = bin(int.from_bytes(text.encode('utf-8', 'surrogatepass'), 'big'))[2:]
        return bits.zfill(8 * ((len(bits) + 7) // 8))
    except: return ""

def bits_to_text(bits):
    try:
        n = int(bits, 2)
        return n.to_bytes((n.bit_length() + 7) // 8, 'big').decode('utf-8', 'surrogatepass')
    except: return "?"

def thread_listener(porta_base):
    sockets = []
    for i in range(4):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setblocking(0)
        try:
            s.bind(('0.0.0.0', porta_base + i))
            sockets.append(s)
        except: pass

    if not sockets:
        print_msg_sistema(f"ERRO CRÍTICO: Portas {porta_base}-{porta_base+3} ocupadas!", "ERRO")
        return

    buffer_bits = ""
    
    while RUNNING: # Variável Global
        try:
            readable, _, _ = select.select(sockets, [], [], 0.2)
            for s in readable:
                data, _ = s.recvfrom(64)
                
                if data == b'FIN':
                    if buffer_bits:
                        texto = ""
                        try:
                            while len(buffer_bits) >= 8:
                                byte = buffer_bits[:8]
                                buffer_bits = buffer_bits[8:]
                                texto += bits_to_text(byte)
                            if texto: print_msg_recebida(texto)
                        except: pass
                        buffer_bits = ""
                    continue

                porta_recebida = s.getsockname()[1]
                offset = porta_recebida - porta_base
                buffer_bits += MAPA_PORTAS.get(offset, "")
        except: pass

# --- FUNÇÃO DE COMANDOS INTERNOS ---
def processar_comando(cmd, ip_dest, porta_base, minha_base):
    global MY_NICK, RUNNING
    
    parts = cmd.split()
    base = parts[0].lower()
    
    if base == "/cls":
        print_header(ip_dest, minha_base, porta_base)
    elif base == "/quit":
        print_msg_sistema("Encerrando conexões...", "INFO")
        RUNNING = False
        time.sleep(0.5)
        sys.exit(0)
    elif base == "/nick":
        if len(parts) > 1:
            MY_NICK = parts[1]
            print_msg_sistema(f"Nick alterado para {MY_NICK}", "INFO")
        else:
            print_msg_sistema("Uso: /nick NovoNome", "ERRO")
    else:
        print_msg_sistema("Comando desconhecido. Use /cls, /nick, /quit", "ERRO")

def loop_sender(ip_destino, porta_destino_base, minha_base_escuta):
    global RUNNING
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    while RUNNING:
        try:
            msg = input()
            
            if not msg:
                # Restaura prompt se enter vazio
                sys.stdout.write(f"{UP_LINE}{CL_LINE}\r{GREEN}{MY_NICK}:{RESET} ")
                sys.stdout.flush()
                continue

            # --- VERIFICAÇÃO DE COMANDOS ---
            if msg.startswith("/"):
                processar_comando(msg, ip_destino, porta_destino_base, minha_base_escuta)
                continue

            # Envio Normal
            print_msg_enviada(msg)
            
            bits = text_to_bits(msg)
            if len(bits) % 2 != 0: bits += "0"
            
            pares = [bits[i:i+2] for i in range(0, len(bits), 2)]
            for par in pares:
                offset = MAPA_BITS[par]
                sock.sendto(b'X', (ip_destino, porta_destino_base + offset))
                time.sleep(0.02) 
            
            for _ in range(3):
                sock.sendto(b'FIN', (ip_destino, porta_destino_base))
                time.sleep(0.01)

        except KeyboardInterrupt:
            print(f"\n{YELLOW}Encerrando...{RESET}")
            RUNNING = False
            sys.exit()
        except: pass

# ==============================================================================
#  MAIN (SETUP)
# ==============================================================================
if __name__ == "__main__":
    os.system('cls' if os.name == 'nt' else 'clear')
    
    # Cores para o menu
    C_SYS = "\033[93m"
    
    print(f"{C_SYS}--- CONFIGURAÇÃO DO AGENTE ---{RESET}")
    print("Para funcionar, UM deve ser A e o OUTRO deve ser B.\n")
    
    print(f" [1] {GREEN}LADO A (Alice){RESET}")
    print(f"     👂 Escuta: 9000, 9001, 9002, 9003")
    print(f"     🗣️  Fala:   9004, 9005, 9006, 9007")
    print("")
    print(f" [2] {CYAN}LADO B (Bob){RESET}")
    print(f"     👂 Escuta: 9004, 9005, 9006, 9007")
    print(f"     🗣️  Fala:   9000, 9001, 9002, 9003")
    
    escolha = input("\nEscolha sua identidade (1 ou 2): ")
    
    # LÓGICA CRUZADA
    if escolha == '1':
        MINHA_BASE = 9000      # Alice ouve no 9000
        DESTINO_BASE = 9004    # Alice manda pro 9004
        papel_default = "Alice"
    else:
        MINHA_BASE = 9004      # Bob ouve no 9004
        DESTINO_BASE = 9000    # Bob manda pro 9000
        papel_default = "Bob"

    print("\n--- PERSONALIZAÇÃO ---")
    input_nick = input(f"Seu Nickname [{papel_default}]: ")
    MY_NICK = input_nick if input_nick else papel_default
    
    input_peer = input(f"Nickname do Parceiro [Amigo]: ")
    PEER_NICK = input_peer if input_peer else "Amigo"

    ip_amigo = input("\nIP do Parceiro (Ex: 10.0.0.X): ")
    if not ip_amigo: ip_amigo = "127.0.0.1"

    # Inicia Interface
    print_header(ip_amigo, MINHA_BASE, DESTINO_BASE)
    
    # Inicia Thread de Escuta
    t = threading.Thread(target=thread_listener, args=(MINHA_BASE,))
    t.daemon = True
    t.start()
    
    # Inicia Loop de Envio (Agora com a Minha Base para o /cls funcionar)
    loop_sender(ip_amigo, DESTINO_BASE, MINHA_BASE)
