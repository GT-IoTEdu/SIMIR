# SIMIR - Sonda Inteligênte de Monitoramento Interno da Rede

## 🎯 Funcionalidades Implementadas

### ✅ Detecção Avançada de Port Scan
- **Detector personalizado do Zeek**: `port-scan-detector.zeek`
- **Algoritmos inteligentes** para detectar padrões suspeitos
- **Classificação de severidade**: LOW, MEDIUM, HIGH, CRITICAL
- **Análise de threat intelligence** com histórico de IPs
- **Whitelist** para IPs confiáveis

### ✅ Sistema de Alertas por Email
- **Monitor avançado**: `simir-monitor.py` 
- **Envio automático** de emails formatados
- **Rate limiting** para evitar spam
- **HTML formatado** com cores por severidade
- **Deduplicação** de alertas similares

### ✅ Scripts de Gerenciamento
- **Inicialização rápida**: `./start-simir.sh`
- **Controle completo**: `./scripts/simir-control.sh`
- **Auto-start integrado**: Inicia automaticamente no container
- **Interface amigável** com menus e cores

### ✅ Integração Docker
- **Dockerfile atualizado** com dependências Python
- **Entrypoint integrado** com sistema SIMIR
- **Auto-inicialização** do monitor no container
- **Logs centralizados** e organizados

## 🚀 Como Usar

### Inicialização Completa
```bash
# Configura email e inicia tudo
./start-simir.sh
```

### Gerenciamento
```bash
# Interface completa
./scripts/simir-control.sh

# Comandos diretos
./scripts/simir-control.sh configure    # Configurar email
./scripts/simir-control.sh start        # Iniciar tudo
./scripts/simir-control.sh status       # Ver status
./scripts/simir-control.sh simulate     # Testar detecção
```

## 📧 Configuração de Email

### Obter App Password do Gmail:
1. Acesse https://myaccount.google.com/
2. Segurança > Verificação em duas etapas
3. Senhas de app > Mail
4. Copie a senha de 16 caracteres

### Configurar:
```bash
./scripts/simir-control.sh configure
```

## 🔍 Tipos de Detecção

### Port Scan Horizontal
- Múltiplas portas em um host
- Threshold: 10+ portas diferentes

### Port Scan Vertical  
- Mesma porta em múltiplos hosts
- Detecção de varreduras em rede

### Tentativas em Portas Fechadas
- Conexões rejeitadas suspeitas
- Indicador de reconnaissance

### Portas Críticas
- SSH (22), RDP (3389), SMB (445)
- HTTP/HTTPS (80, 443)
- Telnet (23), SNMP (161)

## 📊 Monitoramento

### Status em Tempo Real
```bash
./scripts/simir-control.sh status
```

### Logs
- **Monitor**: `/tmp/simir_monitor.log`
- **Container**: `docker-compose logs`
- **Zeek**: `/usr/local/zeek/spool/zeek/notice.log`

### Testes
```bash
# Simular port scan
./scripts/simir-control.sh simulate

# Testar email
./scripts/simir-control.sh test-email
```

## 🛡️ Características de Segurança

### Rate Limiting
- Máximo 10 alertas por hora por tipo
- Cooldown de 5 minutos entre alertas similares
- Alertas críticos têm prioridade

### Threat Intelligence
- Histórico de comportamento por IP
- Score de risco dinâmico
- Análise de padrões temporais

### Configurações Ajustáveis
- Threshold de detecção
- Lista de portas críticas  
- Whitelist de IPs
- Parâmetros de rate limiting

## 📁 Arquivos Principais

### Scripts SIMIR
- `scripts/simir-monitor.py` - Monitor principal
- `scripts/simir-control.sh` - Interface de controle
- `scripts/simir-autostart.sh` - Auto-inicialização
- `scripts/config-email.sh` - Configuração simplificada de email
- `start-simir.sh` - Inicialização rápida

### Configuração Zeek
- `site/port-scan-detector.zeek` - Detector personalizado
- `site/local.zeek` - Configuração principal
- `scripts/entrypoint.sh` - Entrypoint integrado

### Docker
- `Dockerfile` - Imagem com Python e SIMIR
- `docker-compose.yml` - Orchestração
- `README.md` - Documentação completa

## ✅ Status da Implementação

### ✅ Concluído
- [x] Detector de port scan personalizado
- [x] Monitor Python avançado 
- [x] Sistema de alertas por email
- [x] Scripts de gerenciamento
- [x] Integração Docker completa
- [x] Auto-inicialização no container
- [x] Interface de controle amigável
- [x] Documentação completa
- [x] Sistema de testes

### 🔄 Próximos Passos (Opcionais)
- [ ] Dashboard web (futuro)
- [ ] Integração com SIEM (futuro)
- [ ] API REST para controle (futuro)

## 🎉 Resultado

O sistema SIMIR agora está **100% funcional** com:

1. **Detecção automática** de port scans
2. **Alertas por email** para rafaelbartorres@gmail.com
3. **Interface de gerenciamento** completa
4. **Monitoramento robusto** e confiável
5. **Documentação clara** e abrangente

**O sistema está pronto para detectar e alertar sobre atividades suspeitas na rede!** 🚨
