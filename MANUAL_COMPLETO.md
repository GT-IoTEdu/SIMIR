# Manual Completo da Sonda SIMIR

## 📋 Índice
1. [Visão Geral](#visão-geral)
2. [O que é o Zeek](#o-que-é-o-zeek)
3. [Como o SIMIR Funciona](#como-o-simir-funciona)
4. [Instalação e Configuração](#instalação-e-configuração)
5. [Arquivos de Log do Zeek](#arquivos-de-log-do-zeek)
6. [Sistema de Detecção de Port Scan](#sistema-de-detecção-de-port-scan)
7. [Sistema de Detecção de Força Bruta](#sistema-de-detecção-de-força-bruta)
8. [Intelligence Framework](#intelligence-framework)
9. [Gerenciamento do Sistema](#gerenciamento-do-sistema)
10. [Troubleshooting](#troubleshooting)
11. [Monitoramento Avançado](#monitoramento-avançado)
12. [Referências](#referências)

---

## 🎯 Visão Geral

A **SIMIR** (Sonda Inteligente de Monitoramento Interno da Rede) é um sistema completo de monitoramento de rede baseado no **Zeek** (anteriormente conhecido como Bro), com funcionalidades avançadas de detecção de port scan e sistema de alertas por email.

### Características Principais:
- 🔍 **Monitoramento passivo** de tráfego de rede
- 🚨 **Detecção automática** de port scans
- �️ **Detecção de ataques de força bruta** em SSH, FTP e HTTP
- �📧 **Alertas por email** em tempo real
- 🐳 **Containerizado** com Docker
- 🛡️ **Análise de threat intelligence**
- 📊 **Logs estruturados** em formato JSON/TSV

---

## 🔬 O que é o Zeek

### Definição
O **Zeek** é uma plataforma de monitoramento de segurança de rede que fornece visibilidade abrangente do tráfego de rede. Diferente de firewalls ou sistemas de detecção de intrusão tradicionais, o Zeek atua como um "sensor passivo" que analisa o tráfego sem interferir na comunicação.

### Como o Zeek Monitora a Rede

#### 1. **Captura de Pacotes**
```
[Interface de Rede] → [Zeek Engine] → [Scripts de Análise] → [Logs Estruturados]
```

O Zeek utiliza o **libpcap** para capturar pacotes diretamente da interface de rede:
- Modo **promíscuo**: Captura todo o tráfego que passa pela interface
- **Análise em tempo real**: Processa pacotes conforme chegam
- **Zero impacto**: Não interfere no tráfego da rede

#### 2. **Análise de Protocolos**
O Zeek possui parsers nativos para dezenas de protocolos:
- **Camada 3**: IP, ICMP, IPv6
- **Camada 4**: TCP, UDP
- **Aplicação**: HTTP, HTTPS, DNS, SSH, FTP, SMTP, etc.

#### 3. **Geração de Eventos**
Para cada conexão ou atividade detectada, o Zeek gera **eventos**:
```zeek
event connection_established(c: connection) {
    # Evento gerado quando conexão TCP é estabelecida
}

event http_request(c: connection, method: string, original_URI: string) {
    # Evento gerado para cada requisição HTTP
}
```

#### 4. **Scripts Personalizados**
Scripts Zeek (em linguagem própria) definem:
- Quais eventos monitorar
- Como processar os dados
- Que logs gerar
- Quando emitir alertas

### Vantagens do Zeek

#### **Visibilidade Completa**
- Registra **todas** as conexões de rede
- Extrai metadados detalhados (não o conteúdo)
- Identifica protocolos automaticamente

#### **Flexibilidade**
- Scripts totalmente customizáveis
- Integração com sistemas externos
- Formato de logs configurável

#### **Performance**
- Processamento em alta velocidade
- Baixo overhead de CPU/memória
- Escalável para redes de grande porte

---

## ⚙️ Como a SIMIR Funciona

### Arquitetura do Sistema

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Tráfego de    │    │      Zeek        │    │     Sonda     │
│     Rede        │───▶│   Container      │───▶│     SIMIR       │
│                 │    │                  │    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                              │                        │
                              ▼                        ▼
                       ┌──────────────┐       ┌─────────────────┐
                       │   Logs do    │       │   Alertas por   │
                       │     Zeek     │       │     Email       │
                       └──────────────┘       └─────────────────┘
```

### Fluxo de Detecção

1. **Captura**: Zeek monitora interface de rede
2. **Análise**: Scripts personalizados detectam padrões
3. **Logging**: Eventos são registrados em logs
4. **Monitoramento**: Sonda SIMIR lê logs continuamente
5. **Detecção**: Algoritmos identificam port scans
6. **Alerta**: Emails são enviados automaticamente

### Componentes da SIMIR

#### **Container Zeek**
- Engine principal de monitoramento
- Scripts de detecção customizados
- Geração de logs estruturados

#### **Monitor Python**
- Análise inteligente de logs
- Sistema de threat intelligence
- Rate limiting de alertas
- Envio de emails

#### **Scripts de Gerenciamento**
- Configuração automatizada
- Controle do sistema
- Testes e simulação

---

## 🚀 Instalação e Configuração

### Pré-requisitos

#### Sistema Operacional
- **Linux** (Ubuntu, Debian, CentOS, etc.)
- **Docker** e **Docker Compose**
- **Git** para clonagem do repositório

#### Hardware Mínimo
- **CPU**: 2 cores
- **RAM**: 4GB
- **Disco**: 10GB livre
- **Rede**: Interface para monitoramento

### Instalação Passo a Passo

#### 1. **Clonar o Repositório**
```bash
git clone <URL_DO_REPOSITORIO> simir
cd simir
```

#### 2. **Instalar Dependências**
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install -y docker.io docker-compose git python3

# CentOS/RHEL
sudo yum install -y docker docker-compose git python3

# Iniciar Docker
sudo systemctl start docker
sudo systemctl enable docker

# Adicionar usuário ao grupo docker (opcional)
sudo usermod -aG docker $USER
# (faça logout/login após este comando)
```

#### 3. **Configurar Interface de Rede**

**Identificar Interfaces Disponíveis:**
```bash
ip addr show
# ou
ifconfig
```

**Editar Configuração:**
```bash
# Edite docker-compose.yml
nano docker-compose.yml

# Altere a linha:
environment:
  - ZEEK_INTERFACE=sua_interface_aqui  # ex: eth0, enp0s3, etc.
```

#### 4. **Configuração Rápida**
```bash
# Opção 1: Inicialização automática
./start-simir.sh

# Opção 2: Passo a passo
docker-compose build
./scripts/config-email.sh          # Configurar email
docker-compose up -d               # Iniciar container
./scripts/simir-control.sh start-monitor  # Iniciar monitor
```

#### 5. **Verificar Funcionamento**
```bash
# Ver status
./scripts/simir-control.sh status

# Ver logs
docker-compose logs -f

# Testar detecção
./scripts/simir-control.sh simulate
```

### Configuração de Email

#### Configurar Gmail para Alertas

1. **Ativar Verificação em Duas Etapas**
   - Acesse: https://myaccount.google.com/security
   - Clique em "Verificação em duas etapas"
   - Siga o processo de ativação

2. **Gerar App Password**
   - Após ativar 2FA, vá em "Senhas de app"
   - Selecione "Mail" e digite "SIMIR"
   - Copie a senha de 16 caracteres

3. **Configurar na SIMIR**
   ```bash
   ./scripts/config-email.sh
   ```

4. **Testar Configuração**
   ```bash
   ./scripts/simir-control.sh test-email
   ```

---

## 📊 Arquivos de Log do Zeek

O Zeek gera diversos tipos de logs, cada um com informações específicas sobre diferentes aspectos do tráfego de rede.

### Localização dos Logs
```bash
# Dentro do container
/usr/local/zeek/spool/zeek/

# No host (via docker exec)
docker exec SIMIR_Z ls -la /usr/local/zeek/spool/zeek/
```

### Principais Arquivos de Log

#### 1. **conn.log** - Conexões de Rede
**Descrição**: Registra todas as conexões TCP, UDP e ICMP.

**Campos Principais**:
- `ts`: Timestamp da conexão
- `id.orig_h`: IP de origem
- `id.orig_p`: Porta de origem
- `id.resp_h`: IP de destino
- `id.resp_p`: Porta de destino
- `proto`: Protocolo (tcp/udp/icmp)
- `duration`: Duração da conexão
- `orig_bytes`: Bytes enviados pelo originador
- `resp_bytes`: Bytes enviados pelo respondedor
- `conn_state`: Estado da conexão

**Estados de Conexão Importantes**:
- `S0`: Tentativa de conexão sem resposta
- `S1`: Conexão estabelecida, não finalizada
- `SF`: Conexão normal, finalizada
- `REJ`: Conexão rejeitada
- `S2`: Conexão estabelecida, originador fechou
- `S3`: Conexão estabelecida, respondedor fechou

**Exemplo de Entrada**:
```json
{
  "ts": 1641895234.123456,
  "uid": "CwTLJM1KZJzqZJX7Ng",
  "id.orig_h": "192.168.1.100",
  "id.orig_p": 52341,
  "id.resp_h": "93.184.216.34",
  "id.resp_p": 80,
  "proto": "tcp",
  "duration": 0.164,
  "orig_bytes": 76,
  "resp_bytes": 295,
  "conn_state": "SF"
}
```

#### 2. **http.log** - Tráfego HTTP
**Descrição**: Detalha requisições e respostas HTTP.

**Campos Principais**:
- `method`: Método HTTP (GET, POST, etc.)
- `host`: Host solicitado
- `uri`: URI requisitada
- `status_code`: Código de resposta HTTP
- `user_agent`: User-Agent do cliente
- `request_body_len`: Tamanho do corpo da requisição
- `response_body_len`: Tamanho da resposta

**Exemplo**:
```json
{
  "ts": 1641895234.123456,
  "method": "GET",
  "host": "example.com",
  "uri": "/index.html",
  "status_code": 200,
  "user_agent": "Mozilla/5.0...",
  "request_body_len": 0,
  "response_body_len": 1270
}
```

#### 3. **dns.log** - Consultas DNS
**Descrição**: Registra todas as consultas e respostas DNS.

**Campos Principais**:
- `query`: Nome consultado
- `qtype_name`: Tipo de registro (A, AAAA, MX, etc.)
- `rcode_name`: Código de resposta (NOERROR, NXDOMAIN, etc.)
- `answers`: Respostas retornadas
- `TTL`: Time To Live dos registros

#### 4. **ssl.log** - Conexões TLS/SSL
**Descrição**: Detalhes sobre conexões criptografadas.

**Campos Principais**:
- `server_name`: Nome do servidor (SNI)
- `cert_chain_fuids`: IDs dos certificados
- `subject`: Subject do certificado
- `issuer`: Emissor do certificado
- `version`: Versão TLS/SSL

#### 5. **ssh.log** - Conexões SSH
**Descrição**: Informações sobre sessões SSH.

**Campos Principais**:
- `auth_success`: Sucesso da autenticação
- `auth_attempts`: Tentativas de autenticação
- `client`: Software cliente SSH
- `server`: Software servidor SSH

#### 6. **ftp.log** - Transferências FTP
**Descrição**: Atividade em servidores FTP.

**Campos Principais**:
- `user`: Usuário autenticado
- `password`: Senha (se em texto claro)
- `command`: Comando FTP executado
- `reply_code`: Código de resposta do servidor

#### 7. **smtp.log** - Email SMTP
**Descrição**: Transferência de emails via SMTP.

**Campos Principais**:
- `mailfrom`: Remetente
- `rcptto`: Destinatários
- `date`: Data do email
- `subject`: Assunto
- `helo`: Identificação HELO/EHLO

#### 8. **notice.log** - Alertas e Notices ⭐
**Descrição**: **LOG MAIS IMPORTANTE PARA A SIMIR**. Contém alertas gerados por scripts Zeek, incluindo detecções de port scan.

**Campos Principais**:
- `note`: Tipo de alerta
- `msg`: Mensagem descritiva
- `src`: IP de origem do alerta
- `dst`: IP de destino
- `actions`: Ações tomadas

**Tipos de Alertas Relevantes**:
- `PortScan::Port_Scan`: Port scan detectado
- `PortScan::Port_Scan_Target`: Host sendo escaneado
- `PortScan::Closed_Port_Access`: Tentativas em portas fechadas
- `BruteForce::SSH_Bruteforce`: Ataque de força bruta SSH detectado
- `BruteForce::FTP_Bruteforce`: Ataque de força bruta FTP detectado
- `BruteForce::HTTP_Bruteforce`: Ataque de força bruta HTTP detectado
- `BruteForce::Generic_Bruteforce`: Ataque de força bruta genérico detectado

**Exemplo de Port Scan**:
```json
{
  "ts": 1641895234.123456,
  "note": "PortScan::Port_Scan",
  "msg": "Port scan detectado de 192.168.1.100 para 10 hosts, 25 portas diferentes em 2m30s",
  "src": "192.168.1.100",
  "dst": "192.168.1.0/24",
  "actions": ["Notice::ACTION_LOG"]
}
```

**Exemplo de Força Bruta**:
```json
{
  "ts": 1641895234.123456,
  "note": "BruteForce::SSH_Bruteforce",
  "msg": "Possível ataque de força bruta SSH detectado de 192.168.1.100 para 192.168.1.10 (15 tentativas em 5 minutos)",
  "src": "192.168.1.100",
  "dst": "192.168.1.10",
  "actions": ["Notice::ACTION_LOG"]
}
```

#### 9. **files.log** - Transferências de Arquivos
**Descrição**: Arquivos transferidos via HTTP, FTP, SMTP, etc.

**Campos Principais**:
- `fuid`: ID único do arquivo
- `mime_type`: Tipo MIME
- `filename`: Nome do arquivo
- `source`: Fonte da transferência
- `is_orig`: Direção da transferência

#### 10. **intel.log** - Threat Intelligence
**Descrição**: Matches com feeds de threat intelligence.

**Campos Principais**:
- `indicator`: Indicador matched
- `indicator_type`: Tipo (IP, domain, etc.)
- `sources`: Fontes de intelligence

### Formato dos Logs

#### **TSV (Tab-Separated Values)**
Formato padrão mais antigo:
```
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	conn
#open	2024-07-10-22-15-23
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	duration
1641895234.123456	CwTLJM1KZJzqZJX7Ng	192.168.1.100	52341	93.184.216.34	80	tcp	http	0.164
```

#### **JSON**
Formato moderno configurado na SIMIR:
```json
{
  "ts": 1641895234.123456,
  "uid": "CwTLJM1KZJzqZJX7Ng",
  "id.orig_h": "192.168.1.100",
  "id.orig_p": 52341,
  "id.resp_h": "93.184.216.34",
  "id.resp_p": 80,
  "proto": "tcp",
  "service": "http",
  "duration": 0.164
}
```

### Analisando Logs

#### **Visualizar Logs em Tempo Real**
```bash
# Dentro do container
docker exec -it SIMIR_Z tail -f /usr/local/zeek/spool/zeek/conn.log

# Logs específicos
docker exec -it SIMIR_Z tail -f /usr/local/zeek/spool/zeek/notice.log  # Alertas
docker exec -it SIMIR_Z tail -f /usr/local/zeek/spool/zeek/http.log    # HTTP
docker exec -it SIMIR_Z tail -f /usr/local/zeek/spool/zeek/dns.log     # DNS
```

#### **Filtrar por IP**
```bash
# Conexões de um IP específico
docker exec SIMIR_Z grep "192.168.1.100" /usr/local/zeek/spool/zeek/conn.log

# Consultas DNS de um host
docker exec SIMIR_Z grep "192.168.1.100" /usr/local/zeek/spool/zeek/dns.log
```

#### **Analisar Port Scans**
```bash
# Todos os alertas de port scan
docker exec SIMIR_Z grep "Port_Scan" /usr/local/zeek/spool/zeek/notice.log

# Conexões rejeitadas (possíveis scans)
docker exec SIMIR_Z grep "REJ\|S0" /usr/local/zeek/spool/zeek/conn.log
```

---

## 🔍 Sistema de Detecção de Port Scan

### Como Funciona a Detecção

#### 1. **Monitoramento de Conexões**
O script `port-scan-detector.zeek` monitora o evento `connection_state_remove`, que é gerado quando uma conexão termina.

#### 2. **Rastreamento de Padrões**
Para cada IP, o sistema mantém:
- **Hosts contactados**: Lista de IPs de destino
- **Portas acessadas**: Lista de portas diferentes
- **Número de conexões**: Contador total
- **Timestamps**: Primeiro e último evento

#### 3. **Algoritmos de Detecção**

##### **Port Scan Horizontal**
```zeek
# Detecta quando um IP escaneia múltiplas portas
if (|scanner$ports| >= port_scan_threshold) {
    # Gerar alerta de port scan
}
```

##### **Port Scan Vertical**
```zeek
# Detecta quando um IP é escaneado por múltiplos hosts
if (|target$hosts| >= port_scan_threshold) {
    # Gerar alerta de alvo de scan
}
```

##### **Tentativas em Portas Fechadas**
```zeek
# Detecta múltiplas tentativas rejeitadas
if (connection_failed && scanner$connections >= closed_port_threshold) {
    # Gerar alerta de portas fechadas
}
```

#### 4. **Classificação de Severidade**
O monitor Python analisa os alertas e classifica:

**Fatores de Risco**:
- Número de portas escaneadas
- Portas críticas envolvidas (SSH, RDP, etc.)
- Histórico do IP atacante
- Velocidade do scan

**Níveis de Severidade**:
- **LOW** (1-2 pontos): Atividade suspeita leve
- **MEDIUM** (3-4 pontos): Scan moderado
- **HIGH** (5-7 pontos): Scan intenso
- **CRITICAL** (8+ pontos): Ataque direcionado

### Configurações de Detecção

#### **Parâmetros Ajustáveis**
```json
{
  "detection": {
    "port_scan_threshold": 10,          // Portas para considerar scan
    "time_window_minutes": 5,           // Janela de análise
    "suspicious_ports": [22, 23, 80, 443, 3389, 445, 135, 139],
    "whitelist_ips": ["127.0.0.1", "::1"],
    "closed_port_threshold": 5          // Tentativas em portas fechadas
  }
}
```

#### **Portas Monitoradas**
- **SSH (22)**: Acesso remoto
- **Telnet (23)**: Acesso inseguro
- **HTTP (80)**: Web servers
- **HTTPS (443)**: Web seguro
- **SMB (445)**: Compartilhamento Windows
- **RDP (3389)**: Desktop remoto
- **NetBIOS (135, 139)**: Serviços Windows

### Tipos de Alertas Gerados

#### 1. **Port_Scan**
```
Port scan detectado de 192.168.1.100 para 15 hosts, 25 portas diferentes em 3m45s
```

#### 2. **Port_Scan_Target**
```
Host 192.168.1.10 está sendo escaneado por 5 hosts diferentes
```

#### 3. **Closed_Port_Access**
```
Múltiplas tentativas em portas fechadas de 192.168.1.100 (12 tentativas)
```

### Rate Limiting e Anti-Spam

#### **Cooldown de Alertas**
- **5 minutos** entre alertas similares
- **Máximo 10 alertas** por hora por tipo
- **Severidade CRITICAL** ignora alguns limites

#### **Deduplicação**
- IDs únicos por tipo de alerta + IP
- Histórico de alertas enviados
- Prevenção de spam por scans contínuos

---

## 🛡️ Sistema de Detecção de Força Bruta

### Visão Geral

O sistema de detecção de força bruta da SIMIR complementa a detecção de port scan, identificando tentativas repetidas de autenticação em serviços como SSH, FTP e HTTP. Este sistema monitora padrões de comportamento suspeito que podem indicar ataques automatizados.

### Como Funciona a Detecção

#### 1. **Monitoramento de Protocolos**
O script `brute-force-detector.zeek` monitora múltiplos protocolos:
- **SSH**: Eventos de capacidades do servidor (`ssh_server_capabilities`)
- **FTP**: Respostas de autenticação (`ftp_reply`)
- **HTTP**: Códigos de resposta de autenticação (`http_reply`)
- **Genérico**: Análise de conexões rejeitadas (`connection_state_remove`)

#### 2. **Rastreamento de Tentativas**
Para cada IP de origem, o sistema mantém:
- **Contador de tentativas**: Número total de tentativas de autenticação
- **Timestamps**: Primeira e última tentativa
- **Alvo específico**: IP de destino sendo atacado
- **Tipo de protocolo**: SSH, FTP, HTTP ou genérico

#### 3. **Algoritmos de Detecção**

##### **Detecção SSH**
```zeek
# Detecta múltiplas conexões SSH do mesmo IP
if (attempts >= ssh_bruteforce_threshold) {
    # Gerar alerta de força bruta SSH
}
```

##### **Detecção FTP**
```zeek
# Monitora códigos de erro FTP (530 = login incorrect)
if (reply_code == 530 && attempts >= ftp_bruteforce_threshold) {
    # Gerar alerta de força bruta FTP
}
```

##### **Detecção HTTP**
```zeek
# Monitora códigos 401/403 (unauthorized/forbidden)
if ((status_code == 401 || status_code == 403) && attempts >= http_bruteforce_threshold) {
    # Gerar alerta de força bruta HTTP
}
```

##### **Detecção Genérica**
```zeek
# Analisa conexões rejeitadas ou falhadas
if (conn_state in rejected_states && attempts >= generic_bruteforce_threshold) {
    # Gerar alerta de força bruta genérica
}
```

### Configurações de Detecção

#### **Parâmetros Configuráveis**
```zeek
# Thresholds de detecção
const ssh_bruteforce_threshold = 10 &redef;
const ftp_bruteforce_threshold = 8 &redef;
const http_bruteforce_threshold = 15 &redef;
const generic_bruteforce_threshold = 20 &redef;

# Janela de tempo para análise
const bruteforce_time_window = 5min &redef;
```

#### **Protocolos Monitorados**
- **SSH (porta 22)**: Tentativas de login remoto
- **FTP (porta 21)**: Autenticação em servidores FTP
- **HTTP/HTTPS (portas 80/443)**: Ataques a formulários web
- **Genérico**: Qualquer padrão de conexões rejeitadas

### Tipos de Alertas Gerados

#### 1. **SSH_Bruteforce**
```
Possível ataque de força bruta SSH detectado de 192.168.1.100 para 192.168.1.10 (15 tentativas em 5 minutos)
```

#### 2. **FTP_Bruteforce**
```
Possível ataque de força bruta FTP detectado de 10.0.0.50 para 10.0.0.100 (12 tentativas em 3 minutos)
```

#### 3. **HTTP_Bruteforce**
```
Possível ataque de força bruta HTTP detectado de 203.0.113.25 para 192.168.1.5 (25 tentativas em 8 minutos)
```

#### 4. **Generic_Bruteforce**
```
Possível ataque de força bruta detectado de 172.16.0.10 para 172.16.0.20 (30 tentativas em 10 minutos)
```

### Integração com SIMIR

#### **Ativação do Sistema**
O sistema é ativado automaticamente quando os scripts Zeek são carregados:

```bash
# Verificar se está ativo
docker exec SIMIR_Z grep "brute-force-detector" /usr/local/zeek/logs/current/loaded_scripts.log

# Verificar alertas em tempo real
docker exec SIMIR_Z tail -f /usr/local/zeek/logs/current/notice.log | grep BruteForce
```

#### **Teste do Sistema**
```bash
# Via simir-control.sh
./scripts/simir-control.sh
# Escolher opção 9: "Testar detecção de força bruta"

# Teste direto
./scripts/test-brute-force.sh
```

#### **Opções de Teste**
1. **Teste Simples**: Verificação básica de funcionamento
2. **Teste com Zeek**: Validação com engine Zeek
3. **Monitoramento ao Vivo**: Observação de logs em tempo real
4. **Teste de Sintaxe**: Verificação de scripts Zeek

### Logs e Monitoramento

#### **Verificar Detecções**
```bash
# Alertas de força bruta recentes
docker exec SIMIR_Z grep "BruteForce::" /usr/local/zeek/logs/current/notice.log

# Estatísticas por tipo
docker exec SIMIR_Z grep "BruteForce::" /usr/local/zeek/logs/current/notice.log | cut -d'"' -f8 | sort | uniq -c

# Monitoramento em tempo real
docker exec SIMIR_Z tail -f /usr/local/zeek/logs/current/notice.log | grep --color=always "BruteForce"
```

#### **Análise de Padrões**
```bash
# IPs mais ativos em ataques
docker exec SIMIR_Z grep "BruteForce::" /usr/local/zeek/logs/current/notice.log | grep -o '"src":"[^"]*"' | sort | uniq -c | sort -nr

# Alvos mais atacados
docker exec SIMIR_Z grep "BruteForce::" /usr/local/zeek/logs/current/notice.log | grep -o '"dst":"[^"]*"' | sort | uniq -c | sort -nr
```

### Prevenção de Falsos Positivos

#### **Lista Branca (Whitelist)**
Para evitar alertas desnecessários, configure IPs confiáveis:

```zeek
# Adicionar IPs confiáveis
const bruteforce_whitelist: set[addr] = {
    127.0.0.1,      # Localhost
    192.168.1.1,    # Gateway
    10.0.0.100,     # Servidor de monitoramento
} &redef;
```

#### **Ajuste de Sensibilidade**
```zeek
# Para ambientes com mais tráfego legítimo
const ssh_bruteforce_threshold = 20 &redef;     # Aumentar threshold
const bruteforce_time_window = 10min &redef;    # Aumentar janela de tempo

# Para ambientes mais sensíveis
const ssh_bruteforce_threshold = 5 &redef;      # Diminuir threshold
const bruteforce_time_window = 2min &redef;     # Diminuir janela de tempo
```

### Limitações e Considerações

#### **Limitações Atuais**
- **SSH**: Detecta conexões múltiplas, não falhas de autenticação específicas
- **Criptografia**: Não analisa conteúdo de conexões criptografadas
- **Protocolos customizados**: Limitado aos protocolos padrão suportados

#### **Funcionalidades Futuras**
- Integração com logs de sistema (auth.log, secure.log)
- Detecção de força bruta em outros protocolos (SMTP, IMAP, RDP)
- Análise comportamental avançada
- Integração com threat intelligence feeds
- Rate limiting automático via iptables

### Troubleshooting

#### **Sistema Não Detecta Ataques**
```bash
# Verificar se scripts estão carregados
docker exec SIMIR_Z zeekctl status
docker exec SIMIR_Z grep "brute-force-detector" /usr/local/zeek/logs/current/loaded_scripts.log

# Reinstalar scripts se necessário
docker exec SIMIR_Z zeekctl install
docker exec SIMIR_Z zeekctl restart
```

#### **Muitos Falsos Positivos**
```bash
# Ajustar thresholds
nano site/brute-force-detector.zeek
# Aumentar valores de *_bruteforce_threshold

# Adicionar IPs à whitelist
# Editar bruteforce_whitelist no script
```

#### **Teste Manual**
```bash
# Executar teste de força bruta
./scripts/test-brute-force.sh

# Verificar se alertas são gerados
docker exec SIMIR_Z tail -10 /usr/local/zeek/logs/current/notice.log
```

---

## 🧠 Intelligence Framework

### O que é o Intelligence Framework

O **Intelligence Framework** do Zeek é um sistema avançado que permite usar **feeds de inteligência de ameaças** (IOCs - Indicators of Compromise) para detectar automaticamente atividades maliciosas conhecidas. Este sistema compara o tráfego de rede observado contra bases de dados de indicadores maliciosos.

### Como Funciona

O framework monitora continuamente:
- **IPs maliciosos** em conexões de rede
- **Domínios maliciosos** em consultas DNS
- **URLs maliciosas** em requisições HTTP
- **Hashes de arquivos** maliciosos
- **Outros indicadores** personalizados

```
[Tráfego de Rede] → [Intelligence Framework] → [Comparação com IOCs] → [Alertas]
```

### Arquitetura do Sistema

#### **Componentes Principais**
1. **intelligence-framework.zeek**: Script principal de detecção
2. **Feeds de IOCs**: Bases de dados de indicadores maliciosos
3. **Sistema de alertas**: Notificações quando IOCs são encontrados
4. **Logs de inteligência**: Registro detalhado das detecções

#### **Tipos de IOCs Suportados**
- `Intel::ADDR`: Endereços IP maliciosos
- `Intel::DOMAIN`: Domínios maliciosos
- `Intel::URL`: URLs maliciosas
- `Intel::FILE_HASH`: Hashes de arquivos maliciosos
- `Intel::EMAIL`: Endereços de email maliciosos
- `Intel::USER_NAME`: Nomes de usuário suspeitos

### Configuração e Feeds

#### **Estrutura de Feeds**
```bash
site/intel/
├── malicious-ips.txt      # IPs maliciosos
├── malicious-domains.txt  # Domínios maliciosos
├── malicious-urls.txt     # URLs maliciosas
└── backup/                # Backups automáticos
```

#### **Formato dos Feeds**
```bash
# Exemplo: malicious-ips.txt
#fields	indicator	indicator_type	meta.source	meta.desc
185.220.100.240	Intel::ADDR	TorProject	Tor exit node
192.168.100.100	Intel::ADDR	Internal	IP suspeito interno
```

### Detecções e Alertas

#### **Tipos de Alertas**
- **Intelligence::Intel_Hit**: Indicador genérico detectado
- **Intelligence::Malicious_IP**: IP malicioso identificado
- **Intelligence::Malicious_Domain**: Domínio malicioso acessado
- **Intelligence::Malicious_URL**: URL maliciosa acessada
- **Intelligence::Malicious_Hash**: Hash malicioso encontrado

#### **Exemplo de Alerta**
```json
{
  "ts": 1754608200.123456,
  "note": "Intelligence::Malicious_IP",
  "msg": "IP malicioso detectado: 185.220.100.240 (Fonte: TorProject) - Tor exit node",
  "src": "192.168.1.100",
  "actions": ["Notice::ACTION_LOG"],
  "suppress_for": 3600.0
}
```

### Uso e Operação

#### **Teste do Sistema**
```bash
# Teste automatizado
./scripts/simir-control.sh
# Escolher opção: "10) Testar Intelligence Framework"

# Ou comando direto
./scripts/test-intelligence.sh
```

#### **Atualização de Feeds**
```bash
# Via interface
./scripts/simir-control.sh
# Escolher opção: "11) Atualizar feeds de inteligência"

# Ou comando direto
./scripts/update-intel-feeds.sh
```

#### **Visualização de Logs**
```bash
# Via interface
./scripts/simir-control.sh
# Escolher opção: "12) Ver logs > intel"

# Comandos diretos
tail -f logs/notice_PortScan_BruteForce.log | grep -i "intel\|malicious"
tail -f logs/current/intelligence.log
docker exec SIMIR_Z tail -f /usr/local/zeek/logs/current/intel.log
```

### Integração com Feeds Externos

#### **Feeds Públicos Recomendados**
- **Abuse.ch**: Feodo Tracker, URLhaus
- **Malware Domain List**: Domínios maliciosos
- **Tor Project**: Exit nodes
- **Threat Intelligence Platforms**: Commercial feeds

#### **Automação de Updates**
```bash
# Configurar cron para atualizações automáticas
crontab -e

# Atualizar feeds a cada 6 horas
0 */6 * * * /home/rafael/SIMIR/scripts/update-intel-feeds.sh >/dev/null 2>&1
```

### Personalização

#### **Adicionando Feeds Customizados**
```bash
# Criar novo feed
echo "#fields	indicator	indicator_type	meta.source	meta.desc" > site/intel/custom-feed.txt
echo "evil.domain.com	Intel::DOMAIN	Custom	Domínio interno malicioso" >> site/intel/custom-feed.txt

# Atualizar configuração em intelligence-framework.zeek
nano site/intelligence-framework.zeek
# Adicionar linha: "/usr/local/zeek/share/zeek/site/intel/custom-feed.txt"
```

#### **Configuração de Thresholds**
```zeek
# Em intelligence-framework.zeek
const intel_suppress_time = 1800.0 &redef;  # 30 minutos
const enable_intel_logging = T &redef;
```

### Monitoramento e Métricas

#### **Comandos de Verificação**
```bash
# Verificar feeds carregados
docker exec SIMIR_Z zeek -e "print Intel::read_files;"

# Estatísticas de inteligência
docker exec SIMIR_Z grep -c "Intel::" /usr/local/zeek/logs/current/intel.log

# Status do framework
docker exec SIMIR_Z zeekctl diag | grep -i intel
```

#### **Análise de Performance**
```bash
# Contar IOCs por tipo
grep "Intel::" logs/notice_PortScan_BruteForce.log | \
  jq -r '.note' | sort | uniq -c | sort -nr

# Top IPs maliciosos detectados
grep "Malicious_IP" logs/notice_PortScan_BruteForce.log | \
  jq -r '.src' | sort | uniq -c | sort -nr | head -10
```

### Troubleshooting

#### **Framework Não Carrega**
```bash
# Verificar sintaxe dos scripts
docker exec SIMIR_Z zeek -g site/intelligence-framework.zeek

# Verificar logs de erro
docker exec SIMIR_Z tail /usr/local/zeek/logs/current/stderr.log
```

#### **Feeds Não São Carregados**
```bash
# Verificar formato dos feeds
head -5 site/intel/malicious-ips.txt

# Verificar permissões
ls -la site/intel/

# Recriar índices
docker exec SIMIR_Z zeekctl install
docker exec SIMIR_Z zeekctl restart
```

#### **Muitos Falsos Positivos**
```bash
# Filtrar IPs locais/conhecidos
# Adicionar whitelist no intelligence-framework.zeek
const intel_whitelist_subnets = { 192.168.0.0/16, 10.0.0.0/8 } &redef;
```

---

## 🎛️ Gerenciamento do Sistema

### Scripts de Controle

#### **simir-control.sh** - Interface Principal
```bash
# Menu interativo
./scripts/simir-control.sh

# Comandos diretos
./scripts/simir-control.sh configure     # Configurar email
./scripts/simir-control.sh start         # Iniciar tudo
./scripts/simir-control.sh stop          # Parar tudo
./scripts/simir-control.sh status        # Ver status
./scripts/simir-control.sh test-email    # Testar email
./scripts/simir-control.sh simulate      # Simular port scan
./scripts/simir-control.sh test-bruteforce # Testar força bruta
./scripts/simir-control.sh logs monitor  # Ver logs do monitor
```

#### **start-simir.sh** - Inicialização Rápida
```bash
# Configuração e inicialização automática
./start-simir.sh
```

### Comandos Docker

#### **Gerenciamento de Container**
```bash
# Construir imagem
docker-compose build

# Iniciar serviços
docker-compose up -d

# Ver status
docker-compose ps

# Ver logs
docker-compose logs -f

# Parar serviços
docker-compose down

# Acessar shell do container
docker exec -it SIMIR_Z bash
```

#### **Debugging**
```bash
# Logs detalhados
docker-compose logs --tail=100 SIMIR_Z

# Verificar processos dentro do container
docker exec SIMIR_Z ps aux

# Verificar arquivos de log
docker exec SIMIR_Z ls -la /usr/local/zeek/spool/zeek/

# Verificar configuração Zeek
docker exec SIMIR_Z zeekctl status
```

### Monitoramento de Status

#### **Status do Sistema**
```bash
./scripts/simir-control.sh status
```

**Saída Exemplo**:
```
=== STATUS DO SISTEMA SIMIR ===

Container Zeek:
  ✓ Rodando
  📅 Iniciado em: 2024-07-10
  📋 Logs: Disponíveis

Monitor de Port Scan:
  ✓ Rodando (PID: 12345)
  📊 Logs: 150 linhas
  ⏰ Última atividade: 2024-07-10 22:15:30

Configuração de Email:
  ✓ Configurado
  📧 Remetente: alert@exemplo.com
  📬 Destinatário: rafaelbartorres@gmail.com

Alertas Recentes:
  📨 Total de alertas enviados: 3
  📋 Últimos alertas:
    • 2024-07-10 22:10:15 - Port scan detectado...
    • 2024-07-10 21:45:30 - Tentativas em portas fechadas...
```

#### **Logs de Monitoramento**
```bash
# Logs da Sonda SIMIR
tail -f /tmp/simir_monitor.log

# Logs específicos de alertas
grep -i "alert\|port scan" /tmp/simir_monitor.log

# Status de saúde do container
docker exec SIMIR_Z zeekctl status
```

### Configurações Avançadas

#### **Ajustar Threshold de Detecção**
```bash
# Editar configuração
nano /tmp/simir_config.json

# Ou via variáveis de ambiente
export SIMIR_PORT_SCAN_THRESHOLD=15
export SIMIR_TIME_WINDOW_MINUTES=10
```

#### **Adicionar IPs à Whitelist**
```json
{
  "detection": {
    "whitelist_ips": [
      "127.0.0.1",
      "::1",
      "192.168.1.1",      // Gateway
      "10.0.0.100"        // Scanner legítimo
    ]
  }
}
```

#### **Personalizar Portas Monitoradas**
```json
{
  "detection": {
    "suspicious_ports": [
      22,    // SSH
      23,    // Telnet
      80,    // HTTP
      443,   // HTTPS
      3389,  // RDP
      445,   // SMB
      1433,  // SQL Server
      3306,  // MySQL
      5432   // PostgreSQL
    ]
  }
}
```

---

## 🚨 Troubleshooting

### Problemas Comuns

#### 1. **Container Não Inicia**

**Sintomas**:
```bash
docker-compose ps
# Mostra container como "Exit 1" ou similar
```

**Diagnóstico**:
```bash
docker-compose logs SIMIR_Z
```

**Soluções Comuns**:

##### **Interface de Rede Inválida**
```bash
# Verificar interfaces disponíveis
ip addr show

# Atualizar docker-compose.yml
nano docker-compose.yml
# Alterar ZEEK_INTERFACE para interface correta
```

##### **Permissões Insuficientes**
```bash
# Executar com privilégios
sudo ./scripts/setup-permissions.sh

# Ou executar container como root
# Adicionar em docker-compose.yml:
# user: root
```

#### 2. **Zeek Não Detecta Tráfego**

**Sintomas**:
- Logs vazios ou muito poucos
- Ausência de conn.log ou logs com poucos registros

**Diagnóstico**:
```bash
# Verificar se Zeek está rodando
docker exec SIMIR_Z zeekctl status

# Verificar interface
docker exec SIMIR_Z ip addr show

# Verificar se há tráfego na interface
docker exec SIMIR_Z tcpdump -i eth0 -c 10
```

**Soluções**:

##### **Interface em Modo Bridge**
```bash
# Configurar interface em modo promíscuo
sudo ip link set dev eth0 promisc on

# Verificar configuração
ip link show eth0
```

##### **Firewall Bloqueando**
```bash
# Verificar regras iptables
sudo iptables -L

# Temporariamente desabilitar firewall
sudo iptables -F
sudo iptables -P INPUT ACCEPT
sudo iptables -P FORWARD ACCEPT
sudo iptables -P OUTPUT ACCEPT
```

#### 3. **Email Não Funciona**

**Sintomas**:
```
❌ ERRO: (535, b'5.7.8 Username and Password not accepted')
```

**Soluções**:

##### **Gerar Nova App Password**
1. Acesse: https://myaccount.google.com/security
2. Vá em "Senhas de app"
3. Gere nova senha para "Mail"
4. Reconfigure: `./scripts/config-email.sh`

##### **Verificar 2FA**
```bash
# Confirmar que verificação em duas etapas está ativa
# Na conta Google: Segurança > Verificação em duas etapas
```

##### **Testar Configuração Manualmente**
```bash
# Teste direto Python
python3 -c "
import smtplib
server = smtplib.SMTP('smtp.gmail.com', 587)
server.starttls()
server.login('seu_email@gmail.com', 'app_password_aqui')
print('✅ Autenticação OK')
server.quit()
"
```

#### 4. **Sonda SIMIR Não Inicia**

**Sintomas**:
```bash
./scripts/simir-control.sh status
# Monitor de Port Scan: ✗ Parado
```

**Diagnóstico**:
```bash
# Verificar logs de erro
cat /tmp/simir_monitor.log

# Verificar se Python está disponível
python3 --version

# Testar script manualmente
python3 ./scripts/simir-monitor.py --test-email
```

**Soluções**:

##### **Dependências Python Faltando**
```bash
# Instalar dependências
sudo apt install python3-pip
pip3 install smtplib email
```

##### **Arquivo de Configuração Inválido**
```bash
# Verificar configuração JSON
cat /tmp/simir_config.json | python3 -m json.tool

# Recriar configuração
./scripts/config-email.sh
```

#### 5. **Notice.log Não Sendo Criado** ⭐

**Sintomas**:
- Container Zeek rodando normalmente
- Outros logs (conn.log, dns.log, etc.) sendo gerados
- Ausência do arquivo notice.log

**Diagnóstico**:
```bash
# Verificar se scripts personalizados estão carregados
docker exec SIMIR_Z cat /usr/local/zeek/logs/current/loaded_scripts.log | grep site

# Verificar erros de sintaxe
docker exec SIMIR_Z zeekctl diag
```

**Soluções**:

##### **Scripts Não Carregados**
```bash
# Instalar scripts no Zeek (SEMPRE necessário após modificações)
docker exec SIMIR_Z zeekctl install

# Reiniciar Zeek
docker exec SIMIR_Z zeekctl restart

# Verificar se scripts foram carregados
docker exec SIMIR_Z cat /usr/local/zeek/logs/current/loaded_scripts.log | grep port-scan-detector
```

##### **Erro de Sintaxe no Notice::policy**
```zeek
# INCORRETO (vai gerar erro):
redef Notice::policy += {
    [$pred(n: Notice::Info) = { return T; },
     $action = Notice::ACTION_LOG]
};

# CORRETO:
hook Notice::policy(n: Notice::Info)
{
    add n$actions[Notice::ACTION_LOG];
}
```

##### **Falta de Tráfego para Gerar Notices**
```bash
# Gerar tráfego para testar
docker exec SIMIR_Z curl -s google.com > /dev/null

# Ou simular port scan
nmap -sS -F localhost
```

**Arquivos Importantes**:
- Scripts fonte: `/usr/local/zeek/share/zeek/site/`
- Scripts instalados: `/usr/local/zeek/spool/installed-scripts-do-not-touch/site/`
- Notice.log: `/usr/local/zeek/logs/current/notice.log`

#### 6. **Port Scan Não Detectado**

**Sintomas**:
- Alertas de port scan não aparecem no notice.log
- Comportamento inesperado na detecção de scans

**Diagnóstico**:
```bash
# Verificar últimos eventos no notice.log
docker exec SIMIR_Z tail -n 50 /usr/local/zeek/logs/current/notice.log

# Verificar configuração atual do Zeek
docker exec SIMIR_Z cat /usr/local/zeek/etc/zeekctl.cfg | grep -i "port-scan-detector"

# Testar detecção manualmente
zeek -r <(echo "GET / HTTP/1.1
Host: example.com
Connection: close

") -C -s http.log
```

**Soluções**:

##### **Reinstalar Scripts de Detecção**
```bash
# Reinstalar scripts padrão do Zeek
docker exec SIMIR_Z zeekctl install

# Reiniciar Zeek
docker exec SIMIR_Z zeekctl restart
```

##### **Ajustar Sensibilidade de Detecção**
```json
{
  "detection": {
    "port_scan_threshold": 5,
    "time_window_minutes": 1
  }
}
```

##### **Verificar Conflitos com Outros Sistemas**
```bash
# Verificar se há outros IDS/IPS ativos
sudo iptables -L -v -n

# Desabilitar temporariamente outros sistemas de segurança
sudo systemctl stop snort
sudo systemctl stop suricata
```

#### 7. **Sistema de Força Bruta Não Detecta Ataques**

**Sintomas**:
- Ausência de alertas `BruteForce::*` no notice.log
- Comportamento inesperado na detecção de tentativas de força bruta

**Diagnóstico**:
```bash
# Verificar se script de força bruta está carregado
docker exec SIMIR_Z grep "brute-force-detector" /usr/local/zeek/logs/current/loaded_scripts.log

# Verificar últimos alertas de força bruta
docker exec SIMIR_Z grep "BruteForce::" /usr/local/zeek/logs/current/notice.log

# Testar detecção manualmente
./scripts/test-brute-force.sh
```

**Soluções Comuns**:

##### **Script Não Carregado**
```bash
# Verificar se está no local.zeek
docker exec SIMIR_Z grep "brute-force-detector" /usr/local/zeek/share/zeek/site/local.zeek

# Reinstalar scripts
docker exec SIMIR_Z zeekctl install
docker exec SIMIR_Z zeekctl restart
```

##### **Thresholds Muito Altos**
```bash
# Verificar configuração atual
docker exec SIMIR_Z grep "_threshold" /usr/local/zeek/share/zeek/site/brute-force-detector.zeek

# Ajustar para valores mais sensíveis
# Editar o arquivo e diminuir os valores de threshold
```

##### **Falta de Tráfego para Detectar**
```bash
# Simular tentativas SSH
for i in {1..15}; do ssh -o ConnectTimeout=1 invalid_user@localhost 2>/dev/null; done

# Verificar se alertas foram gerados
docker exec SIMIR_Z tail -10 /usr/local/zeek/logs/current/notice.log | grep BruteForce
```

#### 8. **Muitos Falsos Positivos de Força Bruta**

**Sintomas**:
- Excesso de alertas `BruteForce::*` para atividade legítima
- Alertas para IPs conhecidos e confiáveis

**Soluções**:

##### **Configurar Whitelist**
```bash
# Editar script de detecção
nano site/brute-force-detector.zeek

# Adicionar IPs confiáveis em bruteforce_whitelist
const bruteforce_whitelist: set[addr] = {
    192.168.1.1,    # Gateway
    10.0.0.100,     # Servidor de backup
} &redef;
```

##### **Ajustar Sensibilidade**
```bash
# Aumentar thresholds
const ssh_bruteforce_threshold = 20 &redef;    # Era 10
const ftp_bruteforce_threshold = 15 &redef;    # Era 8
const http_bruteforce_threshold = 30 &redef;   # Era 15

# Aumentar janela de tempo
const bruteforce_time_window = 10min &redef;   # Era 5min
```

---

### ✅ Validação Final do Sistema

#### **Verificar Status Completo**
```bash
# Status geral
./scripts/simir-control.sh status

# Verificar se notice.log existe e está sendo gerado
docker exec SIMIR_Z ls -la /usr/local/zeek/logs/current/notice.log
docker exec SIMIR_Z tail -5 /usr/local/zeek/logs/current/notice.log

# Verificar scripts carregados
docker exec SIMIR_Z grep "port-scan-detector\|brute-force-detector\|local.zeek" /usr/local/zeek/logs/current/loaded_scripts.log
```

#### **Teste de Funcionalidade**
```bash
# 1. Testar detecção de port scan
nmap -sS -F localhost

# 2. Testar detecção de força bruta
./scripts/test-brute-force.sh

# 3. Aguardar alguns segundos e verificar alertas
sleep 10
docker exec SIMIR_Z tail -10 /usr/local/zeek/logs/current/notice.log

# Verificar alertas de força bruta especificamente
docker exec SIMIR_Z grep "BruteForce::" /usr/local/zeek/logs/current/notice.log

# 4. Verificar logs do monitor
tail -20 /tmp/simir_monitor.log

# 5. Testar email (se configurado)
./scripts/simir-control.sh test-email
```

#### **Indicadores de Sucesso**
- ✅ Container Zeek rodando (`docker-compose ps`)
- ✅ Logs sendo gerados (`conn.log`, `dns.log`, `http.log`)
- ✅ **notice.log existe e contém alertas**
- ✅ Scripts personalizados carregados (`port-scan-detector.zeek` e `brute-force-detector.zeek`)
- ✅ Sonda SIMIR processando logs
- ✅ Detecção de port scan funcional
- ✅ Detecção de força bruta funcional
- ✅ Emails funcionando (se configurado)

---

## 📈 Monitoramento Avançado

### Integração com Sistemas de Monitoramento

#### 1. **Prometheus/Grafana**
- Exportar métricas do Zeek para Prometheus
- Criar dashboards no Grafana para visualização

#### 2. **ELK Stack (Elasticsearch, Logstash, Kibana)**
- Enviar logs do Zeek para Elasticsearch
- Analisar e visualizar logs no Kibana

#### 3. **Splunk**
- Integrar com o Splunk para análise avançada
- Criar alertas e relatórios personalizados

### Exemplos de Consultas e Dashboards

#### **Grafana**
- **Painel de Conexões por Protocolo**
  - Gráfico de linhas mostrando número de conexões por protocolo (TCP, UDP, ICMP)
- **Mapa de Calor de Port Scans**
  - Mapa de calor mostrando frequência de tentativas de conexão por porta

#### **Kibana**
- **Descoberta de Logs**
  - Consultar logs em tempo real
  - Filtrar por IP, porta, protocolo, etc.
- **Alertas de Segurança**
  - Criar alertas baseados em consultas salvas
  - Notificações por email, webhook, etc.

#### **Splunk**
- **Painel de Monitoramento em Tempo Real**
  - Visualizar eventos do Zeek em tempo real
  - Filtrar por tipo de evento, severidade, etc.
- **Relatórios Agendados**
  - Criar relatórios diários/semanais sobre atividades suspeitas
  - Envio automático por email

### Exemplos de Consultas

#### **Elasticsearch**
```json
GET zeek-*/_search
{
  "query": {
    "match": {
      "note": "PortScan::Port_Scan"
    }
  }
}
```

#### **Splunk**
```spl
index=zeek sourcetype=zeek:notice note="PortScan::Port_Scan"
| stats count by src, dst
| sort -count
```

---

## 📚 Referências

1. **Documentação Oficial do Zeek**: [zeek.org/docs](https://zeek.org/docs/)
2. **Repositório da SIMIR**: https://github.com/GT-IoTEdu/SIMIR
3. **Manual de Detecção de Força Bruta**: `docs/brute-force-detection.md`
4. **Tutoriais e Artigos**:
   - [Introdução ao Zeek](https://zeek.org/getting-started/)
   - [Monitoramento de Rede com SIMIR](https://medium.com/@seu_usuario/monitoramento-de-rede-com-simir-123456789abc)
5. **Comunidade e Suporte**:
   - [Fórum do Zeek](https://community.zeek.org/)
   - [Grupo do SIMIR no Discord](https://discord.gg/seu_link)

---

**Nota**: Este é um documento vivo e pode ser atualizado com novas informações, tutoriais e referências. O sistema SIMIR agora inclui detecção avançada de ataques de força bruta além da detecção de port scan. Contribuições são bem-vindas!

**Última atualização**: Setembro 2025 - Adicionado Intelligence Framework
