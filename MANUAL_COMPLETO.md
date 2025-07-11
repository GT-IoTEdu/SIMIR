# Manual Completo do Sistema SIMIR

## 📋 Índice
1. [Visão Geral](#visão-geral)
2. [O que é o Zeek](#o-que-é-o-zeek)
3. [Como o SIMIR Funciona](#como-o-simir-funciona)
4. [Instalação e Configuração](#instalação-e-configuração)
5. [Arquivos de Log do Zeek](#arquivos-de-log-do-zeek)
6. [Sistema de Detecção de Port Scan](#sistema-de-detecção-de-port-scan)
7. [Gerenciamento do Sistema](#gerenciamento-do-sistema)
8. [Troubleshooting](#troubleshooting)
9. [Monitoramento Avançado](#monitoramento-avançado)
10. [Referências](#referências)

---

## 🎯 Visão Geral

O **SIMIR** (Sonda Inteligente de Monitoramento Interno da Rede) é um sistema completo de monitoramento de rede baseado no **Zeek** (anteriormente conhecido como Bro), com funcionalidades avançadas de detecção de port scan e sistema de alertas por email.

### Características Principais:
- 🔍 **Monitoramento passivo** de tráfego de rede
- 🚨 **Detecção automática** de port scans
- 📧 **Alertas por email** em tempo real
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

## ⚙️ Como o SIMIR Funciona

### Arquitetura do Sistema

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Tráfego de    │    │      Zeek        │    │     Monitor     │
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
4. **Monitoramento**: SIMIR monitor lê logs continuamente
5. **Detecção**: Algoritmos identificam port scans
6. **Alerta**: Emails são enviados automaticamente

### Componentes do SIMIR

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

3. **Configurar no SIMIR**
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
**Descrição**: **LOG MAIS IMPORTANTE PARA O SIMIR**. Contém alertas gerados por scripts Zeek, incluindo detecções de port scan.

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
Formato moderno configurado no SIMIR:
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
# Logs do monitor SIMIR
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

#### 4. **Monitor SIMIR Não Inicia**

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
docker exec SIMIR_Z grep "port-scan-detector\|local.zeek" /usr/local/zeek/logs/current/loaded_scripts.log
```

#### **Teste de Funcionalidade**
```bash
# 1. Testar detecção de port scan
nmap -sS -F localhost

# 2. Aguardar alguns segundos e verificar alertas
sleep 10
docker exec SIMIR_Z tail -10 /usr/local/zeek/logs/current/notice.log

# 3. Verificar logs do monitor
tail -20 /tmp/simir_monitor.log

# 4. Testar email (se configurado)
./scripts/simir-control.sh test-email
```

#### **Indicadores de Sucesso**
- ✅ Container Zeek rodando (`docker-compose ps`)
- ✅ Logs sendo gerados (`conn.log`, `dns.log`, `http.log`)
- ✅ **notice.log existe e contém alertas**
- ✅ Scripts personalizados carregados
- ✅ Monitor SIMIR processando logs
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
2. **Repositório do SIMIR**: [github.com/seu_usuario/simir](https://github.com/seu_usuario/simir)
3. **Tutoriais e Artigos**:
   - [Introdução ao Zeek](https://zeek.org/getting-started/)
   - [Monitoramento de Rede com SIMIR](https://medium.com/@seu_usuario/monitoramento-de-rede-com-simir-123456789abc)
4. **Comunidade e Suporte**:
   - [Fórum do Zeek](https://community.zeek.org/)
   - [Grupo do SIMIR no Discord](https://discord.gg/seu_link)

---

**Nota**: Este é um documento vivo e pode ser atualizado com novas informações, tutoriais e referências. Contribuições são bem-vindas!
