# SIMIR - Sonda Inteligente de Monitoramento Interno da Rede
Sonda integrante do projeto GT-IoTEdu

### ⚡ Inicialização Rápida

```bash
# Configuração e inicialização completa em um comando
./start-simir.sh
```

### 🔧 Gerenciamento Avançado

```bash
# Interface completa de gerenciamento
./scripts/simir-control.sh

# Ou comandos diretos:
./scripts/simir-control.sh configure     # Configurar email
./scripts/simir-control.sh start         # Iniciar tudo
./scripts/simir-control.sh status        # Ver status
./scripts/simir-control.sh simulate      # Simular port scan
```

## Estrutura do Projeto

```
├── docker-compose.yml    # Configuração do Docker Compose
├── Dockerfile           # Definição da imagem Docker
├── start-simir.sh       # 🚀 Inicialização rápida com configuração de email
├── dev.sh              # Script principal de desenvolvimento
├── run-test.sh         # Script de teste rápido
├── scripts/            # Scripts do projeto
│   ├── simir-control.sh    # 🎛️ Interface de controle completa
│   ├── simir-monitor.py    # 🔍 Monitor avançado de port scan
│   ├── simir-autostart.sh  # 🤖 Auto-inicialização no container
│   ├── config-email.sh     # 📧 Configuração simplificada de email
│   ├── entrypoint.sh   # Script principal de entrada
│   ├── check-interface.sh  # Verificação de interface de rede
│   ├── setup-permissions.sh  # Configuração de permissões
│   ├── test-container.sh    # Teste do container
│   ├── dev.sh             # Script de desenvolvimento (backup)
│   ├── validate.sh        # Validação do projeto
│   ├── common.sh          # Funções auxiliares
│   └── README.md          # Documentação dos scripts
├── site/               # Configurações e scripts Zeek
│   ├── local.zeek     # Configuração principal
│   ├── port-scan-detector.zeek  # 🚨 Detector de port scan personalizado
│   ├── detect-port-scan.zeek
│   └── port-scan.zeek
├── etc/               # Configurações adicionais
├── logs/              # Logs do Zeek
└── docs/              # Documentação
```

## 🚨 Sistema de Detecção de Port Scan

### Características:
- **Detecção Inteligente**: Algoritmos avançados para identificar padrões de port scan
- **Alertas por Email**: Notificações automáticas para rafaelbartorres@gmail.com
- **Análise de Severidade**: Classificação de ameaças (LOW, MEDIUM, HIGH, CRITICAL)
- **Rate Limiting**: Evita spam de alertas com cooldown inteligente
- **Threat Intelligence**: Histórico e reputação de IPs
- **Whitelist**: IPs confiáveis não geram alertas

### Tipos de Detecção:
- **Port Scan Horizontal**: Múltiplas portas em um host
- **Port Scan Vertical**: Mesma porta em múltiplos hosts  
- **Tentativas em Portas Fechadas**: Conexões rejeitadas suspeitas
- **Scans Críticos**: Portas sensíveis (SSH, RDP, SMB, etc.)

## Como usar

### 🚀 Método Recomendado - Inicialização Rápida
```bash
# Configura email e inicia sistema completo
./start-simir.sh
```

### 🎛️ Gerenciamento Avançado
```bash
# Interface interativa completa
./scripts/simir-control.sh

# Comandos específicos
./scripts/simir-control.sh configure     # Configurar email para alertas
./scripts/simir-control.sh start         # Iniciar Zeek + Monitor
./scripts/simir-control.sh stop          # Parar tudo
./scripts/simir-control.sh status        # Status completo do sistema
./scripts/simir-control.sh test-email    # Testar envio de email
./scripts/simir-control.sh simulate      # Simular port scan para teste
./scripts/simir-control.sh logs monitor  # Ver logs do monitor
```

### 📧 Configuração de Email
Para receber alertas automáticos por email:

1. **App Password do Gmail** (obrigatório):
   - Acesse https://myaccount.google.com/
   - Segurança > Verificação em duas etapas
   - Senhas de app > Selecionar Mail
   - Copie a senha de 16 caracteres

2. **Configure através do script**:
   ```bash
   ./scripts/config-email.sh
   ```

3. **Ou use o script de controle**:
   ```bash
   ./scripts/simir-control.sh configure
   ```

### Teste rápido
```bash
./run-test.sh
```

### Comandos de desenvolvimento
```bash
# Ver todos os comandos disponíveis
./dev.sh help

# Construir a imagem
./dev.sh build

# Iniciar container
./dev.sh start

# Ver logs em tempo real
./dev.sh logs-f

# Acessar shell do container
./dev.sh shell

# Testar interface de rede
./dev.sh test-iface
```

### Comandos manuais do Docker
```bash
# Construir e iniciar
docker-compose up -d

# Ver logs
docker logs -f SIMIR_Z

# Parar
docker-compose down
```

## Configuração

### Interface de Rede
A interface de rede padrão é `enx000ec89f6cc0`. Para alterar, modifique a variável `ZEEK_INTERFACE` no `docker-compose.yml`.

### Variáveis de Ambiente (docker-compose.yml)
```yaml
environment:
  - ZEEK_INTERFACE=enx000ec89f6cc0
  - SIMIR_SENDER_EMAIL=simir.alerts@gmail.com
  - SIMIR_EMAIL_PASSWORD=sua_app_password_aqui
  - SIMIR_RECIPIENT_EMAIL=rafaelbartorres@gmail.com
```

### Configurações de Detecção
O sistema pode ser ajustado através do arquivo de configuração JSON:
- **Threshold de Port Scan**: Número de portas para considerar scan (padrão: 10)
- **Janela de Tempo**: Período de análise (padrão: 5 minutos)
- **Portas Suspeitas**: Lista de portas críticas monitoradas
- **Whitelist de IPs**: IPs que não geram alertas
- **Rate Limiting**: Controle de frequência de alertas

## 📊 Monitoramento e Logs

### Status do Sistema
```bash
./scripts/simir-control.sh status
```

### Logs em Tempo Real
```bash
# Logs do monitor SIMIR
./scripts/simir-control.sh logs monitor

# Logs do container Zeek
./scripts/simir-control.sh logs zeek

# Apenas alertas
./scripts/simir-control.sh logs alerts
```

### Arquivo de Logs
- **Monitor SIMIR**: `/tmp/simir_monitor.log`
- **Container Zeek**: `docker-compose logs`
- **Zeek Notice**: `/usr/local/zeek/spool/zeek/notice.log`

## 🧪 Testes

### Testar Detecção de Port Scan
```bash
# Simula port scan para testar detecção
./scripts/simir-control.sh simulate

# Ou manualmente com nmap
nmap -sS -F 127.0.0.1
```

### Testar Email
```bash
./scripts/simir-control.sh test-email
```

## Troubleshooting

### Problemas Comuns

#### Email não está sendo enviado
1. Verifique se configurou App Password (não senha normal)
2. Teste conexão: `./scripts/simir-control.sh test-email`
3. Verifique logs: `./scripts/simir-control.sh logs monitor`

#### Port scan não está sendo detectado
1. Verifique se o Zeek está rodando: `./scripts/simir-control.sh status`
2. Simule um scan: `./scripts/simir-control.sh simulate`
3. Verifique logs do Zeek: `./scripts/simir-control.sh logs zeek`

#### Container não inicia
1. Verifique interface de rede no docker-compose.yml
2. Execute permissões: `sudo ./scripts/setup-permissions.sh`
3. Reconstrua: `docker-compose build --no-cache`

### Logs Detalhados
Consulte `scripts/README.md` para informações detalhadas sobre troubleshooting.

### Comandos de Diagnóstico
```bash
# Status completo
./scripts/simir-control.sh status

# Reconstruir sistema
docker-compose down
docker-compose build --no-cache
./start-simir.sh

# Verificar interface de rede
ip addr show
```

### Suporte
Para problemas específicos, verifique os logs em:
- `/tmp/simir_monitor.log` (monitor)
- `docker-compose logs` (container)
- `/usr/local/zeek/spool/zeek/` (logs do Zeek)
