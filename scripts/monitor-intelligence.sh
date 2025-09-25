#!/bin/bash

# Script para monitorar e verificar o funcionamento do Intelligence Framework do SIMIR
# Este script mostra várias maneiras de confirmar que o sistema está detectando ameaças

echo "🔍 VERIFICAÇÃO DO INTELLIGENCE FRAMEWORK - SIMIR"
echo "=============================================="
echo "📅 $(date)"
echo ""

# ========================================================================
# 1. Verificar Status do Container
# ========================================================================
echo "1️⃣ STATUS DO CONTAINER ZEEK"
echo "----------------------------"
if command -v docker-compose &> /dev/null; then
    if docker-compose ps 2>/dev/null | grep -q "zeek.*Up"; then
        echo "✅ Container Zeek está rodando"
        container_status="running"
    elif docker-compose ps 2>/dev/null | grep -q "zeek"; then
        status=$(docker-compose ps | grep zeek | awk '{print $6}')
        echo "⚠️  Container Zeek status: $status"
        container_status="issues"
    else
        echo "❌ Container Zeek não encontrado"
        container_status="not_found"
    fi
else
    echo "❌ docker-compose não disponível"
    container_status="no_docker"
fi

echo ""

# ========================================================================
# 2. Verificar Arquivos de Feeds
# ========================================================================
echo "2️⃣ ARQUIVOS DE THREAT INTELLIGENCE"
echo "-----------------------------------"
intel_dir="/home/rafael/SIMIR/site/intel"
if [ -d "$intel_dir" ]; then
    echo "✅ Diretório de intelligence encontrado: $intel_dir"
    echo ""
    
    total_feeds=0
    total_indicators=0
    
    echo "📊 Resumo dos Feeds Ativos:"
    for file in "$intel_dir"/*.txt; do
        if [ -f "$file" ]; then
            name=$(basename "$file")
            count=$(grep -v "^#\|^$" "$file" 2>/dev/null | wc -l)
            if [ "$count" -gt 0 ]; then
                echo "  ✅ $name: $count indicadores"
                total_indicators=$((total_indicators + count))
                ((total_feeds++))
            else
                echo "  ⚠️  $name: arquivo vazio ou apenas cabeçalhos"
            fi
        fi
    done
    
    echo ""
    echo "📈 Total: $total_feeds feeds ativos com $total_indicators indicadores"
    
    # Verificar tipos de IOCs
    if [ "$total_indicators" -gt 0 ]; then
        echo ""
        echo "📋 Breakdown por tipo de IOC:"
        ip_count=$(grep -h "Intel::ADDR" "$intel_dir"/*.txt 2>/dev/null | wc -l)
        domain_count=$(grep -h "Intel::DOMAIN" "$intel_dir"/*.txt 2>/dev/null | wc -l)
        url_count=$(grep -h "Intel::URL" "$intel_dir"/*.txt 2>/dev/null | wc -l)
        hash_count=$(grep -h "Intel::FILE_HASH" "$intel_dir"/*.txt 2>/dev/null | wc -l)
        
        [ "$ip_count" -gt 0 ] && echo "  🌐 IPs maliciosos: $ip_count"
        [ "$domain_count" -gt 0 ] && echo "  🏗️  Domínios maliciosos: $domain_count"
        [ "$url_count" -gt 0 ] && echo "  🔗 URLs maliciosas: $url_count"
        [ "$hash_count" -gt 0 ] && echo "  #️⃣  Hashes de arquivos: $hash_count"
    fi
    
    # Verificar feeds do Suricata especificamente
    suricata_feeds=$(ls "$intel_dir"/suricata-*.txt 2>/dev/null | wc -l)
    if [ "$suricata_feeds" -gt 0 ]; then
        echo ""
        echo "🛡️  Feeds do Suricata encontrados: $suricata_feeds"
        for suricata_file in "$intel_dir"/suricata-*.txt; do
            if [ -f "$suricata_file" ]; then
                name=$(basename "$suricata_file")
                count=$(grep -v "^#" "$suricata_file" | wc -l)
                echo "  • $name: $count IOCs"
            fi
        done
    fi
else
    echo "❌ Diretório de intelligence não encontrado: $intel_dir"
fi

echo ""

# ========================================================================
# 3. Verificar Configuração do Zeek
# ========================================================================
echo "3️⃣ CONFIGURAÇÃO DO FRAMEWORK"
echo "-----------------------------"
config_file="/home/rafael/SIMIR/site/intelligence-framework.zeek"
if [ -f "$config_file" ]; then
    echo "✅ Arquivo de configuração encontrado"
    
    # Contar feeds configurados
    feed_count=$(grep -c '"/usr/local/zeek/share/zeek/site/intel/.*\.txt"' "$config_file")
    echo "📂 Feeds configurados no Zeek: $feed_count"
    
    # Verificar se feeds do Suricata estão incluídos
    if grep -q "suricata-" "$config_file"; then
        echo "✅ Feeds do Suricata incluídos na configuração"
    else
        echo "⚠️  Feeds do Suricata não encontrados na configuração"
    fi
    
    # Verificar sintaxe básica
    if grep -q "Intel::read_files" "$config_file" && grep -q "};" "$config_file"; then
        echo "✅ Sintaxe básica da configuração parece correta"
    else
        echo "❌ Possível problema de sintaxe na configuração"
    fi
else
    echo "❌ Arquivo de configuração não encontrado: $config_file"
fi

echo ""

# ========================================================================
# 4. Verificar Logs do Zeek
# ========================================================================
echo "4️⃣ LOGS E DETECÇÕES"
echo "-------------------"

if [ "$container_status" = "running" ]; then
    # Verificar se conseguimos acessar logs dentro do container
    if docker-compose exec -T zeek test -d "/usr/local/zeek/logs/current" 2>/dev/null; then
        echo "✅ Diretório de logs acessível no container"
        
        # Verificar arquivos de log específicos
        log_files=("conn.log" "notice.log" "intel.log" "dns.log" "http.log")
        for log_file in "${log_files[@]}"; do
            if docker-compose exec -T zeek test -f "/usr/local/zeek/logs/current/$log_file" 2>/dev/null; then
                size=$(docker-compose exec -T zeek stat -c%s "/usr/local/zeek/logs/current/$log_file" 2>/dev/null)
                if [ "$size" -gt 0 ]; then
                    echo "  ✅ $log_file: ${size} bytes"
                    
                    # Verificar detecções de intelligence especificamente
                    if [ "$log_file" = "intel.log" ]; then
                        detections=$(docker-compose exec -T zeek wc -l "/usr/local/zeek/logs/current/intel.log" 2>/dev/null | awk '{print $1}')
                        if [ "$detections" -gt 1 ]; then  # > 1 porque primeira linha é cabeçalho
                            echo "    🎯 Detecções de intelligence: $((detections - 1))"
                        fi
                    fi
                    
                    if [ "$log_file" = "notice.log" ]; then
                        notices=$(docker-compose exec -T zeek wc -l "/usr/local/zeek/logs/current/notice.log" 2>/dev/null | awk '{print $1}')
                        if [ "$notices" -gt 1 ]; then
                            echo "    🚨 Alertas gerados: $((notices - 1))"
                        fi
                    fi
                else
                    echo "  ⚠️  $log_file: arquivo vazio"
                fi
            else
                echo "  ❌ $log_file: não encontrado"
            fi
        done
        
        # Verificar estatísticas de rede
        echo ""
        echo "📊 ESTATÍSTICAS DE MONITORAMENTO:"
        if docker-compose exec -T zeek test -f "/usr/local/zeek/logs/current/conn.log" 2>/dev/null; then
            connections=$(docker-compose exec -T zeek tail -n +2 "/usr/local/zeek/logs/current/conn.log" 2>/dev/null | wc -l)
            echo "  🌐 Conexões monitoradas: $connections"
        fi
        
        if docker-compose exec -T zeek test -f "/usr/local/zeek/logs/current/dns.log" 2>/dev/null; then
            dns_queries=$(docker-compose exec -T zeek tail -n +2 "/usr/local/zeek/logs/current/dns.log" 2>/dev/null | wc -l)
            echo "  🔍 Consultas DNS: $dns_queries"
        fi
        
        if docker-compose exec -T zeek test -f "/usr/local/zeek/logs/current/http.log" 2>/dev/null; then
            http_requests=$(docker-compose exec -T zeek tail -n +2 "/usr/local/zeek/logs/current/http.log" 2>/dev/null | wc -l)
            echo "  🌍 Requisições HTTP: $http_requests"
        fi
        
    else
        echo "⚠️  Não foi possível acessar logs no container"
    fi
else
    echo "⚠️  Container não está rodando - não é possível verificar logs"
fi

echo ""

# ========================================================================
# 5. Teste de Detecção Simples
# ========================================================================
echo "5️⃣ TESTE DE DETECÇÃO"
echo "--------------------"

if [ "$container_status" = "running" ] && [ "$total_indicators" -gt 0 ]; then
    echo "🧪 Executando teste básico de detecção..."
    
    # Pegar um IP malicioso dos feeds para teste
    test_ip=$(grep -h "Intel::ADDR" "$intel_dir"/*.txt 2>/dev/null | head -1 | cut -f1)
    
    if [ -n "$test_ip" ]; then
        echo "📍 IP de teste selecionado: $test_ip"
        
        # Simular consulta DNS ou ping (se possível) para gerar tráfego
        echo "🔄 Gerando tráfego de teste..."
        
        # Tentar ping simples (pode não funcionar dependendo da rede)
        if ping -c 1 -W 2 "$test_ip" >/dev/null 2>&1; then
            echo "  ✅ Ping realizado com sucesso"
        else
            echo "  ℹ️  Ping não funcionou (normal se IP estiver offline)"
        fi
        
        # Aguardar um momento para processamento
        sleep 3
        
        # Verificar se houve detecção
        if docker-compose exec -T zeek test -f "/usr/local/zeek/logs/current/intel.log" 2>/dev/null; then
            recent_detections=$(docker-compose exec -T zeek tail -n 5 "/usr/local/zeek/logs/current/intel.log" 2>/dev/null | grep -v "^#")
            if [ -n "$recent_detections" ]; then
                echo "  🎯 Detecções recentes encontradas!"
                echo "$recent_detections" | while read -r line; do
                    echo "    • $line"
                done
            else
                echo "  ℹ️  Nenhuma detecção recente (normal se não houve tráfego malicioso)"
            fi
        fi
    else
        echo "  ⚠️  Nenhum IP malicioso encontrado nos feeds para teste"
    fi
else
    echo "⚠️  Não é possível executar teste (container parado ou sem feeds)"
fi

echo ""

# ========================================================================
# 6. Recomendações
# ========================================================================
echo "6️⃣ RECOMENDAÇÕES E PRÓXIMOS PASSOS"
echo "-----------------------------------"

if [ "$container_status" = "running" ] && [ "$total_indicators" -gt 0 ]; then
    echo "✅ Sistema está funcionando corretamente!"
    echo ""
    echo "🚀 Para continuar monitorando:"
    echo "  • Monitore logs: sudo docker-compose logs -f zeek"
    echo "  • Veja detecções: sudo docker-compose exec zeek tail -f /usr/local/zeek/logs/current/intel.log"
    echo "  • Verifique alertas: sudo docker-compose exec zeek tail -f /usr/local/zeek/logs/current/notice.log"
    echo "  • Atualize feeds: ./scripts/update-threat-feeds.sh"
    echo ""
    echo "⏰ Configure atualizações automáticas:"
    echo "  crontab -e"
    echo "  0 */6 * * * /home/rafael/SIMIR/scripts/update-threat-feeds.sh >/dev/null 2>&1"
else
    echo "⚠️  Sistema precisa de atenção:"
    
    if [ "$container_status" != "running" ]; then
        echo "  • Reinicie o container: sudo docker-compose restart zeek"
        echo "  • Verifique logs de erro: sudo docker-compose logs zeek"
    fi
    
    if [ "$total_indicators" -eq 0 ]; then
        echo "  • Baixe feeds: ./scripts/update-threat-feeds.sh"
        echo "  • Teste feeds do Suricata: ./scripts/test-suricata-feeds.sh"
    fi
fi

echo ""
echo "🔍 Verificação concluída em $(date)"
