# Sistema de Detecção de Força Bruta - SIMIR

## Visão Geral

O `brute-force-detector.zeek` é um script personalizado do Zeek que detecta tentativas de ataques de força bruta em diferentes serviços de rede. Este sistema trabalha em conjunto com o detector de port scan para fornecer uma proteção abrangente contra ataques automatizados.

## Arquitetura Técnica

### Componentes Principais

1. **Detector Principal** (`brute-force-detector.zeek`)
   - Módulo Zeek com namespace `BruteForce`
   - Sistema de rastreamento baseado em estruturas `auth_tracker`
   - Eventos para SSH, FTP, HTTP e detecção genérica

2. **Sistema de Teste** (`test-brute-force.zeek` e `test-brute-force.sh`)
   - Script de simulação de ataques
   - Interface automatizada de testes
   - Validação de sintaxe e configuração

3. **Integração Docker**
   - Container `SIMIR_Z` executando Zeek
   - Volume compartilhado para logs
   - Sincronização automática de arquivos

### Fluxo de Detecção

```
Tráfego de Rede → Zeek → Events (SSH/FTP/HTTP/Generic) → 
Tracker Update → Threshold Check → Notice Generation → 
Log Files → SIMIR Monitoring
```

## Funcionalidades

### Tipos de Detecção

1. **SSH Brute Force**: Detecta tentativas de força bruta em serviços SSH
2. **FTP Brute Force**: Detecta tentativas de força bruta em serviços FTP  
3. **HTTP Brute Force**: Detecta tentativas de força bruta em aplicações web
4. **Generic Brute Force**: Detecta padrões suspeitos em portas de autenticação
5. **Successful After Failures**: Detecta autenticações bem-sucedidas após múltiplas falhas (implementação futura)

### Configurações Padrão

- **SSH Threshold**: 5 tentativas falhadas
- **FTP Threshold**: 5 tentativas falhadas
- **HTTP Threshold**: 10 tentativas falhadas
- **Generic Threshold**: 8 tentativas falhadas
- **Janela de Tempo**: 10 minutos
- **Success After Failures**: 3 falhas antes do sucesso (implementação futura)

## Arquivos

- `brute-force-detector.zeek` - Script principal de detecção
- `test-brute-force.zeek` - Script de teste para validação
- `test-brute-force.sh` - Script automatizado de testes
- `local.zeek` - Configuração atualizada para carregar o detector

## Como Funciona

### Detecção SSH
- Monitora conexões SSH falhadas (porta 22) através do evento `connection_state_remove`
- Identifica conexões com estados: "REJ", "S0", "RSTO", "RSTR"
- Rastreia tentativas por IP de origem e hosts de destino
- Gera alertas quando o threshold é atingido

### Detecção FTP
- Monitora códigos de resposta FTP (530, 421, 425) através do evento `ftp_reply`
- Rastreia tentativas falhadas por IP de origem
- Gera alertas quando o threshold é atingido

### Detecção HTTP
- Monitora códigos de resposta HTTP 401 e 403 através do evento `http_reply`
- Rastreia tentativas de autenticação falhadas
- Útil para detectar ataques a formulários de login web

### Detecção Genérica
- Monitora conexões rejeitadas/falhadas em portas de autenticação
- Portas monitoradas: 21, 22, 23, 25, 80, 110, 143, 443, 993, 995, 1433, 3306, 3389, 5432
- Backup para serviços não cobertos pelos detectores específicos
- Exclui SSH (porta 22) que tem tratamento específico

## Configuração

### Personalização de Thresholds

Edite o arquivo `brute-force-detector.zeek` para ajustar os thresholds:

```zeek
# Configurações
global ssh_failed_threshold = 5;      # Tentativas SSH falhadas
global ftp_failed_threshold = 5;      # Tentativas FTP falhadas  
global http_failed_threshold = 10;    # Tentativas HTTP falhadas
global generic_failed_threshold = 8;  # Tentativas genéricas falhadas
global time_window = 10min;           # Janela de tempo para análise
global success_after_failures = 3;    # Sucessos após falhas para alerta
```

### Ativação

O detector é carregado automaticamente através do `local.zeek` quando o container SIMIR está em execução. Para uso manual:

```bash
# Usando o sistema SIMIR (recomendado)
sudo /home/rafael/SIMIR/scripts/simir-control.sh test-brute

# Ou através do script de teste específico
sudo /home/rafael/SIMIR/scripts/test-brute-force.sh --test

# Para execução manual no container
sudo docker exec SIMIR_Z zeek -C /usr/local/zeek/share/zeek/site/brute-force-detector.zeek
```

## Logs e Alertas

### Tipos de Notice Gerados

1. `SSH_Brute_Force` - Força bruta SSH detectada
2. `FTP_Brute_Force` - Força bruta FTP detectada
3. `HTTP_Brute_Force` - Força bruta HTTP detectada
4. `Generic_Brute_Force` - Força bruta genérica detectada
5. `Successful_After_Failures` - Sucesso após múltiplas falhas (implementação futura)

### Localização dos Logs

Os alertas são registrados no arquivo `notice.log` do Zeek quando ataques são detectados. Localização:
- **Container:** `/usr/local/zeek/spool/zeek/notice.log`
- **Host:** `/home/rafael/SIMIR/logs/notice.log`

### Verificação de Logs

```bash
# Ver alertas em tempo real
tail -f /home/rafael/SIMIR/logs/notice.log

# Ver últimos logs do container
sudo docker logs --tail 20 SIMIR_Z

# Verificar se há arquivo de alertas
ls -la /home/rafael/SIMIR/logs/notice.log
```

## Teste

Para testar o sistema de detecção, use o script integrado:

```bash
# Teste completo através do menu SIMIR
sudo /home/rafael/SIMIR/scripts/simir-control.sh
# Escolha opção 9: "Testar detector de força bruta"

# Teste direto por linha de comando
sudo /home/rafael/SIMIR/scripts/simir-control.sh test-brute

# Ou usando o script específico
sudo /home/rafael/SIMIR/scripts/test-brute-force.sh --test

# Apenas verificar sintaxe
sudo /home/rafael/SIMIR/scripts/test-brute-force.sh --syntax

# Verificar configurações
sudo /home/rafael/SIMIR/scripts/test-brute-force.sh --config

# Monitoramento em tempo real
sudo /home/rafael/SIMIR/scripts/test-brute-force.sh --live
```

Os testes executarão simulações de ataques de força bruta para validar o funcionamento do detector.

## Integração com SIMIR

O detector de força bruta se integra completamente com o sistema SIMIR:

1. **Carregamento Automático**: Incluído no `local.zeek` e carregado automaticamente no container
2. **Logging JSON**: Configurado para gerar logs em formato JSON
3. **Monitoramento**: Integrado com o sistema de monitoramento do SIMIR via Docker
4. **Alertas**: Compatível com o sistema de notificação por email (quando configurado)
5. **Interface**: Acessível através do menu principal do SIMIR
6. **Testes**: Sistema de testes automatizado integrado

### Comandos de Integração

```bash
# Status do sistema completo
sudo /home/rafael/SIMIR/scripts/simir-control.sh status

# Verificar logs de todos os tipos
sudo /home/rafael/SIMIR/scripts/simir-control.sh logs alerts

# Menu interativo principal
sudo /home/rafael/SIMIR/scripts/simir-control.sh
```

## Troubleshooting

### Problemas Comuns

1. **Muitos alertas falso-positivos**:
   - Aumente os thresholds de detecção no arquivo `brute-force-detector.zeek`
   - Ajuste a janela de tempo (`time_window`)
   - Revise as regras de exclusão para tráfego legítimo

2. **Não detecta ataques conhecidos**:
   - Verifique se o container SIMIR está em execução: `sudo docker ps | grep SIMIR`
   - Verifique se os serviços estão sendo monitorados nos logs: `tail -f /home/rafael/SIMIR/logs/conn.log`
   - Diminua os thresholds de detecção temporariamente para teste
   - Execute o teste de sintaxe: `sudo /home/rafael/SIMIR/scripts/test-brute-force.sh --syntax`

3. **Performance impact**:
   - Aumente a janela de tempo (`time_window`) para reduzir frequência de análise
   - Reduza o número de serviços monitorados removendo portas da função `is_auth_port`
   - Monitore uso de recursos do container: `sudo docker stats SIMIR_Z`

4. **Container não inicia**:
   - Verifique interface de rede no `docker-compose.yml`
   - Verifique logs do container: `sudo docker logs SIMIR_Z`
   - Reinicie o container: `sudo docker compose restart zeek`

5. **Arquivo notice.log não é criado**:
   - Normal se não há ataques detectados
   - Execute teste de simulação: `sudo /home/rafael/SIMIR/scripts/test-brute-force.sh --test`
   - Verifique permissões do diretório de logs: `ls -la /home/rafael/SIMIR/logs/`

### Debugging

Para habilitar debugging detalhado, adicione ao script:

```zeek
# No início do arquivo brute-force-detector.zeek
@load base/utils/debug

# Em qualquer função
print fmt("Debug: %s", variavel);
```

### Comandos Úteis de Debugging

```bash
# Verificar sintaxe do script
sudo docker exec SIMIR_Z zeek -C /usr/local/zeek/share/zeek/site/brute-force-detector.zeek

# Monitorar logs em tempo real
sudo docker exec SIMIR_Z tail -f /usr/local/zeek/spool/zeek/stderr.log

# Verificar se o script está carregado
sudo docker exec SIMIR_Z grep -r "brute-force-detector" /usr/local/zeek/share/zeek/site/

# Status do Zeek no container
sudo docker exec SIMIR_Z zeekctl status

# Reiniciar o Zeek no container
sudo docker exec SIMIR_Z zeekctl restart
```

## Melhorias Futuras

### Implementação Planejada
- **Successful After Failures**: Detectar autenticações bem-sucedidas após múltiplas falhas
- **Detecção de ataques distribuídos**: Correlação entre múltiplos IPs atacantes
- **Machine Learning**: Algoritmos para reduzir falsos positivos baseado em padrões históricos
- **Integração com threat intelligence**: Feeds externos de IPs maliciosos conhecidos

### Funcionalidades Avançadas
- **Análise comportamental**: Perfis de usuários para detectar anomalias
- **Correlação com eventos de port scan**: Combinação de detecções para alertas consolidados
- **Dashboard web**: Interface gráfica para visualização em tempo real
- **API REST**: Endpoints para integração com sistemas externos
- **Notificações push**: Alertas em tempo real via webhooks ou Slack

### Otimizações
- **Performance**: Otimização para ambientes de alta carga
- **Armazenamento**: Compressão e rotação automática de logs
- **Configuração dinâmica**: Ajuste de thresholds sem reinicialização
