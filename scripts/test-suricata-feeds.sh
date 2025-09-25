#!/bin/bash

# Script para testar a integração de feeds do Suricata no SIMIR
# Este script baixa uma amostra de regras e extrai IOCs para demonstração

INTEL_DIR="/home/rafael/SIMIR/site/intel"
TEMP_DIR="/tmp/simir_suricata_test"

echo "🧪 Testando integração de feeds do Suricata..."
echo "📅 $(date)"
echo ""

# Criar diretório temporário
mkdir -p "$TEMP_DIR"

# ========================================================================
# Funções de teste
# ========================================================================

# Função para extrair IOCs das regras do Suricata
extract_suricata_iocs() {
    local input="$1"
    local output="$2"
    local rule_type="$3"

    echo "#fields	indicator	indicator_type	meta.source	meta.desc" > "$output"
    
    echo "  🔍 Analisando regras de $rule_type..."
    
    # Extrair IPs das regras
    local ip_count=0
    grep -oP '(?<=[\s\[])[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(?=[\s\]/])' "$input" | sort -u | while read -r ip; do
        # Filtrar IPs privados e inválidos
        if [[ ! "$ip" =~ ^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|0\.|255\.) ]]; then
            echo -e "$ip\tIntel::ADDR\tSuricata-$rule_type\tIP extraído de regras Suricata $rule_type" >> "$output"
            ((ip_count++))
        fi
    done
    
    # Extrair domínios das regras
    local domain_count=0
    grep -oP '(?<=[\s";\[])[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]*\.([a-zA-Z]{2,}|[a-zA-Z]{2,}\.[a-zA-Z]{2,})(?=[\s";/\]])' "$input" | \
    grep -E '\.(com|org|net|edu|gov|mil|int|co\.|ru|cn|de|uk|fr|it|es|pl|nl|br|au|ca|jp|kr|in|mx|tw|tr|se|ch|be|dk|no|fi|at|cz|pt|gr|il|za|my|th|sg|ph|vn|id|eg|ar|cl|pe|ve|ec|uy|py|bo|gq|tk|ml|ga|cf|ly|sy|iq|af|pk|bd|lk|mm|kh|la|mn|bt|np|mv|fj|to|ws|tv|nu|ck|pw|vu|sb|ki|nr|mh|fm|as|gu|vi|pr|um)$' | \
    sort -u | while read -r domain; do
        if [[ "$domain" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
            echo -e "$domain\tIntel::DOMAIN\tSuricata-$rule_type\tDomínio extraído de regras Suricata $rule_type" >> "$output"
            ((domain_count++))
        fi
    done
    
    return $((ip_count + domain_count))
}

# ========================================================================
# Teste de download e processamento
# ========================================================================

echo "🌐 Baixando regras do Suricata para teste..."

# Testar regras de Botnet C&C
echo "  🤖 Testando regras de Botnet C&C..."
if curl -s --connect-timeout 15 --max-time 30 \
    "https://rules.emergingthreats.net/open/suricata/rules/emerging-botcc.rules" \
    -o "$TEMP_DIR/test_botcc.rules"; then
    
    if [ -s "$TEMP_DIR/test_botcc.rules" ]; then
        echo "    📁 Arquivo baixado: $(wc -l < "$TEMP_DIR/test_botcc.rules") linhas"
        
        # Mostrar algumas regras de exemplo
        echo "    📋 Exemplos de regras encontradas:"
        grep -m 3 "alert.*msg:" "$TEMP_DIR/test_botcc.rules" | head -3 | while read -r rule; do
            msg=$(echo "$rule" | grep -oP 'msg:"[^"]*"' | head -1)
            echo "      • $msg"
        done
        
        # Extrair IOCs
        extract_suricata_iocs "$TEMP_DIR/test_botcc.rules" "$TEMP_DIR/test_botcc_iocs.txt" "BotCC"
        ioc_count=$(grep -v "^#" "$TEMP_DIR/test_botcc_iocs.txt" | wc -l)
        
        if [ "$ioc_count" -gt 0 ]; then
            echo "    ✅ $ioc_count IOCs extraídos!"
            echo "    📊 Breakdown:"
            ip_count=$(grep "Intel::ADDR" "$TEMP_DIR/test_botcc_iocs.txt" | wc -l)
            domain_count=$(grep "Intel::DOMAIN" "$TEMP_DIR/test_botcc_iocs.txt" | wc -l)
            echo "      ├─ IPs maliciosos: $ip_count"
            echo "      └─ Domínios maliciosos: $domain_count"
            
            # Mostrar alguns exemplos
            if [ "$ip_count" -gt 0 ]; then
                echo "    🔍 Exemplos de IPs extraídos:"
                grep "Intel::ADDR" "$TEMP_DIR/test_botcc_iocs.txt" | head -3 | while read -r line; do
                    ip=$(echo "$line" | cut -f1)
                    echo "      • $ip"
                done
            fi
            
            if [ "$domain_count" -gt 0 ]; then
                echo "    🔍 Exemplos de domínios extraídos:"
                grep "Intel::DOMAIN" "$TEMP_DIR/test_botcc_iocs.txt" | head -3 | while read -r line; do
                    domain=$(echo "$line" | cut -f1)
                    echo "      • $domain"
                done
            fi
        else
            echo "    ⚠️  Nenhum IOC extraído desta fonte"
        fi
    else
        echo "    ❌ Arquivo vazio recebido"
    fi
else
    echo "    ❌ Falha no download"
fi

echo ""

# Testar regras de IPs comprometidos
echo "  💀 Testando regras de IPs comprometidos..."
if curl -s --connect-timeout 15 --max-time 30 \
    "https://rules.emergingthreats.net/open/suricata/rules/emerging-compromised.rules" \
    -o "$TEMP_DIR/test_compromised.rules"; then
    
    if [ -s "$TEMP_DIR/test_compromised.rules" ]; then
        echo "    📁 Arquivo baixado: $(wc -l < "$TEMP_DIR/test_compromised.rules") linhas"
        
        # Extrair IOCs
        extract_suricata_iocs "$TEMP_DIR/test_compromised.rules" "$TEMP_DIR/test_compromised_iocs.txt" "Compromised"
        ioc_count=$(grep -v "^#" "$TEMP_DIR/test_compromised_iocs.txt" | wc -l)
        
        if [ "$ioc_count" -gt 0 ]; then
            echo "    ✅ $ioc_count IOCs extraídos!"
            ip_count=$(grep "Intel::ADDR" "$TEMP_DIR/test_compromised_iocs.txt" | wc -l)
            domain_count=$(grep "Intel::DOMAIN" "$TEMP_DIR/test_compromised_iocs.txt" | wc -l)
            echo "    📊 IPs: $ip_count, Domínios: $domain_count"
        else
            echo "    ⚠️  Nenhum IOC extraído desta fonte"
        fi
    else
        echo "    ❌ Arquivo vazio recebido"
    fi
else
    echo "    ❌ Falha no download"
fi

# ========================================================================
# Teste de integração com o sistema
# ========================================================================
echo ""
echo "🔧 Testando integração com o sistema SIMIR..."

# Verificar se o diretório de intel existe
if [ -d "$INTEL_DIR" ]; then
    echo "  ✅ Diretório de intelligence encontrado: $INTEL_DIR"
    
    # Copiar arquivos de teste para o diretório de produção (se existirem)
    test_files_copied=0
    for test_file in "$TEMP_DIR"/test_*_iocs.txt; do
        if [ -f "$test_file" ] && [ -s "$test_file" ]; then
            base_name=$(basename "$test_file" | sed 's/test_//g' | sed 's/_iocs//g')
            target_file="$INTEL_DIR/suricata-${base_name}.txt"
            
            cp "$test_file" "$target_file"
            echo "  📄 Copiado: $(basename "$target_file") ($(grep -v "^#" "$target_file" | wc -l) entradas)"
            ((test_files_copied++))
        fi
    done
    
    if [ "$test_files_copied" -gt 0 ]; then
        echo "  ✅ $test_files_copied arquivo(s) de teste copiados para produção"
    else
        echo "  ⚠️  Nenhum arquivo de teste válido para copiar"
    fi
else
    echo "  ❌ Diretório de intelligence não encontrado: $INTEL_DIR"
fi

# Verificar configuração do Zeek
config_file="/home/rafael/SIMIR/site/intelligence-framework.zeek"
if [ -f "$config_file" ]; then
    echo "  ✅ Arquivo de configuração do Zeek encontrado"
    
    # Verificar se feeds do Suricata estão configurados
    if grep -q "suricata-" "$config_file"; then
        echo "  ✅ Feeds do Suricata já configurados no Zeek"
    else
        echo "  ⚠️  Feeds do Suricata não encontrados na configuração"
        echo "     Execute: ./scripts/update-threat-feeds.sh para configurar automaticamente"
    fi
else
    echo "  ❌ Arquivo de configuração do Zeek não encontrado"
fi

# ========================================================================
# Relatório final
# ========================================================================
echo ""
echo "📊 Relatório do Teste de Integração Suricata:"
echo "============================================"

total_iocs=0
for file in "$INTEL_DIR"/suricata-*.txt; do
    if [ -f "$file" ]; then
        name=$(basename "$file")
        count=$(grep -v "^#" "$file" | wc -l 2>/dev/null || echo "0")
        echo "  📄 $name: $count IOCs"
        total_iocs=$((total_iocs + count))
    fi
done

echo ""
echo "📈 Total de IOCs do Suricata: $total_iocs"
echo ""

if [ "$total_iocs" -gt 0 ]; then
    echo "✅ Integração com Suricata funcionando!"
    echo ""
    echo "🚀 Próximos passos:"
    echo "  1. Execute: ./scripts/update-threat-feeds.sh (para atualização completa)"
    echo "  2. Configure cron para atualizações automáticas"
    echo "  3. Monitor logs em: docker-compose logs SIMIR_Z"
    echo "  4. Teste detecções com: ./scripts/test-intelligence.sh"
else
    echo "⚠️  Nenhum IOC extraído. Verifique conectividade e fontes."
fi

# Limpeza
rm -rf "$TEMP_DIR"

echo ""
echo "🧪 Teste concluído!"
