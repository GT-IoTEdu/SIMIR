# Integração de Feeds do Suricata com SIMIR

## 📋 Visão Geral

O SIMIR agora suporta extração automatizada de Indicadores de Comprometimento (IOCs) diretamente das regras do Suricata. Este recurso permite aproveitar a inteligência de ameaças incorporada nas assinaturas do Suricata para alimentar o framework de threat intelligence do Zeek.

## 🎯 Fontes de Feeds Suricata Suportadas

### Emerging Threats Rules
- **Botnet C&C**: `emerging-botcc.rules` - Extrai IPs e domínios de command & control
- **IPs Comprometidos**: `emerging-compromised.rules` - Extrai IPs conhecidamente comprometidos  
- **Malware**: `emerging-malware.rules` - Extrai IOCs relacionados a malware
- **Trojan**: `emerging-trojan.rules` - Extrai IOCs de trojans

### Fontes Adicionais Disponíveis
- **CI Army**: `emerging-ciarmy.rules` - Lista de IPs maliciosos mantida pela comunidade
- **Tor**: `emerging-tor.rules` - Nós de saída Tor
- **DShield**: `emerging-dshield.rules` - Feeds do SANS DShield

## 🔧 Como Funciona

### 1. Extração de IOCs
O sistema analisa as regras do Suricata e extrai:
- **IPs Maliciosos**: Endereços IP referenciados nas regras
- **Domínios Maliciosos**: Domínios mencionados em regras de detecção
- **URLs**: URLs maliciosas (quando disponíveis)

### 2. Filtragem Inteligente
- Remove IPs privados e de loopback
- Filtra domínios de exemplo e teste
- Elimina duplicatas
- Valida formato dos IOCs

### 3. Conversão para Formato Zeek
Os IOCs extraídos são convertidos para o formato esperado pelo framework de intelligence do Zeek:
```
#fields	indicator	indicator_type	meta.source	meta.desc
1.2.3.4	Intel::ADDR	Suricata-BotCC	IP extraído de regras Suricata BotCC
malware.example.com	Intel::DOMAIN	Suricata-Malware	Domínio extraído de regras Suricata Malware
```

## 🚀 Uso Prático

### Atualização Automática
```bash
# Executar atualização completa (inclui feeds do Suricata)
./scripts/update-threat-feeds.sh
```

### Teste da Integração
```bash
# Testar especificamente os feeds do Suricata
./scripts/test-suricata-feeds.sh
```

### Configuração no Cron
```bash
# Agendar atualizações automáticas a cada 6 horas
crontab -e

# Adicionar linha:
0 */6 * * * /home/rafael/SIMIR/scripts/update-threat-feeds.sh >/dev/null 2>&1
```

## 📊 Arquivos Gerados

### Localização
- **Diretório**: `/home/rafael/SIMIR/site/intel/`
- **Formato**: `suricata-[tipo].txt`

### Tipos de Arquivos
- `suricata-botcc.txt` - IOCs de botnet C&C
- `suricata-compromised.txt` - IPs comprometidos
- `suricata-malware.txt` - IOCs de malware

### Exemplo de Conteúdo
```
#fields	indicator	indicator_type	meta.source	meta.desc
185.220.100.240	Intel::ADDR	Suricata-BotCC	IP extraído de regras Suricata BotCC
bad-domain.ru	Intel::DOMAIN	Suricata-Malware	Domínio extraído de regras Suricata Malware
```

## 🔍 Monitoramento e Logs

### Verificar Status dos Feeds
```bash
# Listar todos os feeds ativos
ls -la /home/rafael/SIMIR/site/intel/suricata-*.txt

# Contar IOCs por tipo
grep -c "Intel::ADDR" /home/rafael/SIMIR/site/intel/suricata-*.txt
grep -c "Intel::DOMAIN" /home/rafael/SIMIR/site/intel/suricata-*.txt
```

### Logs de Detecção
```bash
# Ver detecções recentes
docker-compose exec SIMIR_Z tail -f /usr/local/zeek/logs/current/intel.log

# Filtrar apenas detecções do Suricata
grep "Suricata" /usr/local/zeek/logs/current/intel.log
```

## ⚙️ Configuração Avançada

### Personalizar Fontes
Edite `/home/rafael/SIMIR/scripts/update-threat-feeds.sh` para adicionar/remover fontes:

```bash
# Adicionar nova fonte de regras
echo "  🆕 Nova fonte - Custom Rules..."
if curl -s "https://example.com/custom.rules" -o "$TEMP_DIR/custom.rules"; then
    extract_suricata_iocs "$TEMP_DIR/custom.rules" "$INTEL_DIR/suricata-custom.txt" "Custom"
fi
```

### Ajustar Sensibilidade
Edite as funções `extract_suricata_iocs` e `process_suricata_rules` para:
- Modificar regex de extração
- Adicionar filtros específicos
- Customizar descrições dos IOCs

### Integração Manual
```bash
# Baixar regras manualmente
curl -s "https://rules.emergingthreats.net/open/suricata/rules/emerging-botcc.rules" \
     -o /tmp/manual_rules.txt

# Processar manualmente
./scripts/extract-suricata-iocs.sh /tmp/manual_rules.txt output.txt "Manual"
```

## 🛡️ Benefícios da Integração

### 1. **Cobertura Ampliada**
- Aproveita a expertise da comunidade Suricata
- Acesso a IOCs atualizados regularmente
- Múltiplas fontes de threat intelligence

### 2. **Automação Total**
- Atualização automática via cron
- Processamento e conversão automáticos
- Integração transparente com Zeek

### 3. **Qualidade dos IOCs**
- Regras mantidas por especialistas
- Filtragem inteligente de falsos positivos
- Contexto adicional via descrições

### 4. **Flexibilidade**
- Múltiplas fontes configuráveis
- Extração personalizável
- Integração com feeds existentes

## 🔧 Solução de Problemas

### Problemas de Download
```bash
# Verificar conectividade
curl -I https://rules.emergingthreats.net/

# Testar download manual
curl -v "https://rules.emergingthreats.net/open/suricata/rules/emerging-botcc.rules"
```

### Nenhum IOC Extraído
```bash
# Verificar formato das regras baixadas
head -20 /tmp/simir_threat_feeds/et_botcc.rules

# Testar regex manualmente
grep -oP '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' arquivo_regras.txt
```

### Feeds Não Carregados no Zeek
```bash
# Verificar configuração
grep -A 10 "Intel::read_files" /home/rafael/SIMIR/site/intelligence-framework.zeek

# Reiniciar container
docker-compose restart SIMIR_Z
```

## 📈 Métricas e Estatísticas

### Exemplo de Output
```
📊 Resumo dos feeds atualizados:
  📄 suricata-botcc.txt: 1,234 entradas
  📄 suricata-compromised.txt: 567 entradas  
  📄 suricata-malware.txt: 890 entradas

📈 Total de IOCs do Suricata: 2,691
   ├─ IPs maliciosos: 1,856
   └─ Domínios maliciosos: 835
```

## 🎯 Próximos Passos

1. **Executar teste inicial**: `./scripts/test-suricata-feeds.sh`
2. **Atualização completa**: `./scripts/update-threat-feeds.sh`  
3. **Configurar automação**: Adicionar ao cron
4. **Monitorar detecções**: Verificar logs do Zeek
5. **Ajustar configuração**: Personalizar conforme necessário

---

**💡 Dica**: Os feeds do Suricata são atualizados frequentemente. Configure atualizações automáticas para manter a proteção sempre atual!
