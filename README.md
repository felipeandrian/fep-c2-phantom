

````markdown
# 👻 FEP C2 PHANTOM
### Advanced Hybrid Covert Channel (ICMP Steganography & DNS Timing)

![Python](https://img.shields.io/badge/Python-3.x-yellow.svg)
![Type](https://img.shields.io/badge/Type-Asymmetric%20C2-red.svg)
![Stealth](https://img.shields.io/badge/Stealth-Timing%20Channel-blueviolet.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

> **⚠️ Disclaimer (Aviso Legal):**
> Este software é uma **Prova de Conceito (PoC)** desenvolvida estritamente para fins de pesquisa acadêmica em segurança ofensiva, engenharia de redes e análise forense. O autor não encoraja, sanciona ou apoia o uso desta ferramenta para acesso não autorizado a sistemas. O utilizador assume total responsabilidade legal pelas suas ações.

---

## Visão Geral

O **FEP C2 PHANTOM** é um framework de Comando e Controle (C2) assimétrico desenhado para operar em ambientes de rede restritivos e altamente monitorizados.

A ferramenta desafia os modelos tradicionais de deteção ao desacoplar os canais de entrada e saída, utilizando protocolos "silenciosos" e técnicas de ofuscação temporal.

### A Arquitetura "Split-Flow"
1.  **Comando (Inbound):** Injeção esteganográfica em pacotes **ICMP (Ping)**, mimetizando padrões de tráfego legítimo de sistemas Linux para evadir deteção de entropia e assinaturas IDS.
2.  **Exfiltração (Outbound):** Um canal lateral baseado em tempo (**Network Timing Channel**) sobre **UDP/53**. Os dados não existem no payload do pacote, mas sim na modulação temporal (latência) entre os envios.

---

##  Engenharia e Mecânicas de Evasão

O projeto implementa diversas camadas de *Tradecraft* ofensivo para contornar defesas modernas:

### 1. ICMP Masquerading & Fake Reply (Entrada)
Para enviar comandos ao agente sem abrir portas TCP (Bind Shell) ou manter conexões HTTP ruidosas:
* **Raw Sockets:** Manipulação de pacotes em baixo nível para injetar o comando dentro do padrão de preenchimento (*padding*) nativo do Linux (`!"#$%&...`).
* **Consistência de Tamanho:** O payload é mantido com tamanho fixo (64 bytes), evitando anomalias de volume.
* **Evasão de Estado:** Ao receber um comando, o agente gera imediatamente um **Fake Echo Reply** forjado, copiando o ID e Sequence Number originais. Isso satisfaz a tabela de conexões do Firewall, fazendo a transação parecer benigna e completa.

### 2. DNS Timing Channel (Saída)
A exfiltração abandona o envio de dados no corpo do pacote para evitar DPI (Deep Packet Inspection).
* **O Canal Fantasma:** A informação é transmitida modulando o intervalo de tempo (*Inter-Arrival Time*) entre pacotes DNS.
    * `Bit 0` ≈ Atraso Curto (µ 0.4s)
    * `Bit 1` ≈ Atraso Longo (µ 1.2s)
* **Jitter Gaussiano:** O atraso não é fixo. Utilizamos uma distribuição normal (`random.gauss`) para introduzir imperfeições humanas, fazendo o tráfego parecer latência natural da rede.
* **Protocol Mimicry:** Os pacotes transportadores são queries DNS perfeitamente formadas para domínios legítimos.

### 3. Execução "Living off the Land" (Endpoint)
Para evitar a deteção por EDRs (Endpoint Detection & Response):
* O agente evita o uso de `subprocess.Popen` (que cria processos filhos como `cmd.exe`) para comandos comuns.
* Utiliza APIs nativas do Python (`os`, `platform`, `socket`) para reconhecimento do sistema, mantendo a árvore de processos limpa.

---

## Fluxo de Execução

```mermaid
sequenceDiagram
    participant Hacker (C2)
    participant Firewall (NGFW)
    participant Agente (Vítima)

    Note over Hacker, Agente: FASE 1: INJEÇÃO (ICMP)
    Hacker->>Firewall: Echo Req [Payload: "FEP:whoami" camuflado no padrão Linux]
    Firewall->>Agente: Encaminha (Parece Ping normal)
    Agente->>Firewall: Echo Reply [Fake Response imediato]
    Firewall->>Hacker: Encaminha (Sessão Fechada no State Table)
    
    Note over Agente: Execução Silenciosa (Native API)
    
    Note over Hacker, Agente: FASE 2: EXFILTRAÇÃO (TIMING)
    loop Modulação de Bits (Gaussian Jitter)
        Agente->>Firewall: UDP 53 [Query: google.com]
        Firewall->>Hacker: Encaminha (DPI OK: É DNS válido)
        opt Bit 0
            Note right of Agente: Espera ~0.4s (Ruído Natural)
        end
        opt Bit 1
            Note right of Agente: Espera ~1.2s (Ruído Natural)
        end
        Agente->>Firewall: UDP 53 [Query: google.com]
    end
````

-----

##  Instalação e Uso

### Pré-requisitos

  * **Sistema Operacional:** Linux (Recomendado para Raw Sockets) ou Windows (Requer Admin).
  * **Privilégios:** `Root` ou `Administrator` são obrigatórios para a criação de Raw Sockets.

### Clonar o Repositório

```bash
git clone [https://github.com/felipeandrian/fep-c2-phantom.git](https://github.com/felipeandrian/fep-c2-phantom.git)
cd fep-c2-phantom
```

### 1\. Iniciar o Hacker (Listener/Controller)

```bash
sudo python3 hybrid_phantom_final.py
> Hacker (H) ou Agente (A)? H
> IP do Outro Lado: [IP_DO_AGENTE]
```

### 2\. Iniciar o Agente (Implant)

```bash
sudo python3 hybrid_phantom_final.py
> Hacker (H) ou Agente (A)? A
> IP do Outro Lado: [IP_DO_HACKER]
```


-----

## ⚠️ Nota de Pesquisa

Este projeto é uma implementação acadêmica. Uma versão armada (*weaponized*) em comparação com o PoC:

# 1. Limitações do Python e Dependência de Interpretadores
**Contexto:** Python é excelente para prototipagem, mas em ambientes monitorados apresenta limitações significativas.  
- **Desempenho:** Mais lento e deixa artefatos em memória.  
- **Dependências:** Requer interpretador volumoso.  
- **Monitoramento:** É amplamente vigiado por soluções de segurança.  

**Versão avançada:** Reescrita em linguagens compiladas (C, C++ ou Rust), gerando binários nativos pequenos, sem dependências externas e capazes de utilizar chamadas diretas ao sistema.

---

# 2. Infraestrutura e Não-Atribuição
**PoC:** Conexões diretas a servidores de controle expõem o operador.  
**Versão avançada:** Uso de redirecionadores descartáveis e técnicas como *domain fronting*, criando camadas de comunicação que dificultam a atribuição e permitem substituir rapidamente componentes comprometidos.  

**Arquitetura típica:**  
1. **Camada 1 (Vítima):** comunica-se com um domínio legítimo de alta reputação (ex.: CDN).  
2. **Camada 2 (Front):** a CDN encaminha para um servidor intermediário.  
3. **Camada 3 (Team Server):** o intermediário redireciona para o C2 real via túnel criptografado.  

---

# 3. Protocolos e Conformidade RFC
**PoC:** Pacotes artificiais (DNS falso, ICMP customizado) são facilmente detectados por inspeção profunda.  
**Versão avançada:** Tráfego mimetizado bit a bit com comunicações legítimas, como consultas DNS reais ou perfis HTTPS maleáveis, tornando a detecção estatística muito mais difícil.  

**Exemplos:**  
- **DNS Tunneling real:** consultas legítimas a subdomínios, com respostas em registros TXT/A.  
- **HTTPS camuflado:** perfis maleáveis que imitam tráfego de serviços legítimos (ex.: Windows Update).  
---

# 4. Camada de Execução Avançada: Implantes Position Independent  

**Limitação em PoCs:** Scripts (`.py`) ou binários estáticos (`.exe`) dependem do carregador do sistema operacional, gerando eventos de criação de processo e carregando DLLs monitoradas.  

**Versão avançada:**  
- Conversão em **Shellcode PIC (Position Independent Code)**.  
- Código escrito em C/Assembly sem endereços fixos.  
- Injeção em processos já existentes e confiáveis (ex.: `explorer.exe`, `spoolsv.exe`).  
- Benefício: não há arquivo no disco nem processo novo; o tráfego parece originar de um processo legítimo.  

---

# 5. Evasão de EDR e Antivírus  

**Limitação em PoCs:** Bibliotecas padrão (ex.: `socket`, `subprocess`) chamam APIs monitoradas por EDRs modernos.  

**Versão avançada:**  
- Uso de **Direct System Calls**, contornando hooks em DLLs como `ntdll.dll`.  
- Execução direta via instruções de baixo nível, invisível ao monitoramento em *User Mode*.  
- Técnicas de descoberta dinâmica de syscalls permitem saltar por cima dos ganchos de segurança.  

---

# 6. Ocultação em Memória  

**Limitação em PoCs:** Código permanece em memória em texto claro, sujeito a dumps e regras YARA.  

**Versão avançada:**  
- **Sleep Obfuscation:** criptografa memória durante períodos de inatividade, alterando permissões para dificultar varreduras.  
- **Call Stack Spoofing:** falsificação da pilha de chamadas para simular origem em DLLs legítimas, confundindo análises forenses.  

---

# 7. Comunicação em Rede: Perfis Maleáveis  

**Limitação em PoCs:** Tráfego ICMP/DNS com padrões fixos é facilmente detectável.  

**Versão avançada:**  
- Perfis C2 maleáveis que imitam tráfego legítimo.  
- Handshake TLS idêntico ao cliente do Windows Update.  
- Payloads escondidos em XML ou cabeçalhos HTTP legítimos.  
- Benefício: tráfego malicioso se confunde com comunicações normais do sistema.  

---

# 8. Infraestrutura Inteligente  

**Limitação em PoCs:** Expor diretamente o IP do C2 facilita bloqueio e atribuição.  

**Versão avançada:**  
- Uso de redirectors descartáveis e lógica de filtragem.  
- VPS baratos ou sites legítimos comprometidos atuam como proxy.  
- Filtragem decide se encaminha ao C2 ou redireciona para sites legítimos, mascarando investigação.  

---

# Resumo da Transformação  

| Componente | PoC (Acadêmico) | Versão Avançada |
|------------|-----------------|-----------------|
| **Código** | Script Python   | Shellcode PIC   |
| **Execução** | Subprocessos visíveis | Injeção / Direct Syscalls |
| **Memória** | Texto claro    | Sleep Masking   |
| **Rede** | Raw sockets      | Perfis maleáveis |
| **Defesa** | Evasão básica   | Bypass ativo de EDR |


---

# 9. Execução Avançada em Windows e Linux  

**Windows:**  
- Reescrita em C/Assembly como **Position Independent Code (PIC)**.  
- Técnicas como *Reflective DLL Injection* permitem execução em memória de processos confiáveis (`spoolsv.exe`, `notepad.exe`).  
- Benefício: não há arquivo no disco e o tráfego parece originar de processos legítimos.  

**Linux:**  
- Uso de `memfd_create` para criar arquivos anônimos diretamente em RAM.  
- Execução via `fexecve`, sem deixar rastros em diretórios monitorados.  
- *Process masquerading* altera identificadores de processo para simular serviços legítimos (`[kworker/u4:0]`).  

---

# 10. Evasão de Monitoramento  

**Windows:**  
- Uso de **Direct Syscalls**, contornando hooks em DLLs como `ntdll.dll`.  
- Execução direta via instruções de baixo nível, invisível ao monitoramento em *User Mode*.  

**Linux:**  
- Defesa baseada em **eBPF** e monitoramento de kernel.  
- Técnicas avançadas incluem *LD_PRELOAD* para interceptar chamadas de bibliotecas e ocultar conexões, além de módulos de kernel que se desvinculam da lista de carregamento (`lsmod`).  

---

# 11. Comunicação em Rede e Mimetização  

**Windows:**  
- Uso de APIs nativas (`IcmpSendEcho2`, `DnsQuery_A`) para gerar tráfego indistinguível de comunicações legítimas.  
- Consultas DNS realizadas por processos do sistema (`svchost.exe`), mascarando origem.  

**Linux:**  
- Manipulação de tráfego existente, injetando dados em conexões legítimas (ex.: atualizações via `apt-get`).  
- Benefício: tráfego malicioso se confunde com comunicações normais do sistema.  

---

# 12. Ocultação em Memória: Sleep Encryption  

**PoC:** Scripts em Python permanecem em memória em texto claro, facilmente identificável.  

**Versão avançada:**  
- **Sleep Obfuscation:** criptografia da memória durante períodos de inatividade.  
- **Execução cíclica:** descriptografa apenas quando necessário, executa rapidamente e retorna ao estado criptografado.  
- Benefício: dumps de memória revelam apenas dados aleatórios, sem strings ou código legível.  

---

# 13. Comparação Estrutural  

| Vetor        | PoC (Acadêmico) | Versão Avançada (Windows) | Versão Avançada (Linux) |
|--------------|-----------------|---------------------------|-------------------------|
| Linguagem    | Python          | C/Assembly (PIC)          | C/Go (ELF estático)     |
| Rede         | Raw sockets     | APIs nativas (WinINet)    | Packet injection        |
| Execução     | Subprocessos    | Direct Syscalls           | memfd_create / execveAt |
| Persistência | Script no boot  | DLL Hijacking / WMI       | LD_PRELOAD / Cron       |
| Memória      | Texto claro     | Criptografia em repouso   | Criptografia em repouso |
| DNS          | Pacotes falsos  | API do sistema (svchost)  | Resolução legítima      |

---

-----

## 📄 Licença

Distribuído sob a licença MIT. Veja `LICENSE` para mais informações.

Copyright (c) 2025 **Felipe Andrian Peixoto**

```

---
