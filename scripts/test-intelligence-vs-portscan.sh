#!/bin/bash

echo "🔍 TESTE ESPECÍFICO: Intelligence Framework vs Port Scan"
echo "======================================================="

echo ""
echo "1️⃣ VERIFICANDO DIFERENÇA ENTRE AS DETECÇÕES"
echo "-------------------------------------------"

echo "📊 Análise dos logs atuais:"
echo ""

# Contar tipos de detecções no notice.log
portscan_detections=$(sudo docker-compose exec -T zeek grep -c "PortScan::" "/usr/local/zeek/logs/current/notice.log" 2>/dev/null || echo "0")
intel_detections=$(sudo docker-compose exec -T zeek grep -c "Intelligence::" "/usr/local/zeek/logs/current/notice.log" 2>/dev/null || echo "0")

echo "🚨 Port Scan detections: $portscan_detections"
echo "🎯 Intelligence detections: $intel_detections"

echo ""
echo "2️⃣ O QUE SÃO AS DETECÇÕES ATUAIS:"
echo "--------------------------------"

echo "🔍 Port Scan detections (últimas 3):"
sudo docker-compose exec -T zeek tail -3 "/usr/local/zeek/logs/current/notice.log" | while read -r line; do
    note=$(echo "$line" | jq -r '.note')
    msg=$(echo "$line" | jq -r '.msg')
    src=$(echo "$line" | jq -r '.src')
    echo "  • $note: $msg (IP: $src)"
done

echo ""
echo "3️⃣ VERIFICANDO CARREGAMENTO DE FEEDS"
echo "-----------------------------------"

# Verificar se os feeds estão sendo carregados
echo "📂 Feeds configurados:"
grep "intel.*\.txt" /home/rafael/SIMIR/site/intelligence-framework.zeek | while read -r line; do
    feed=$(echo "$line" | grep -o '[^/]*\.txt' | tr -d '",')
    if [ -n "$feed" ]; then
        if [ -f "/home/rafael/SIMIR/site/intel/$feed" ]; then
            count=$(grep -v "^#\|^$" "/home/rafael/SIMIR/site/intel/$feed" | wc -l)
            echo "  ✅ $feed: $count IOCs"
        else
            echo "  ❌ $feed: arquivo não encontrado"
        fi
    fi
done

echo ""
echo "4️⃣ TESTANDO IP ESPECÍFICO DOS FEEDS"
echo "----------------------------------"

# Pegar um IP específico dos feeds para teste
test_ip=$(grep -v "^#" /home/rafael/SIMIR/site/intel/malicious-ips.txt | head -1 | cut -f1)
if [ -n "$test_ip" ]; then
    echo "🎯 Testando IP do feed: $test_ip"
    
    # Verificar se está realmente no feed
    if grep -q "$test_ip" /home/rafael/SIMIR/site/intel/malicious-ips.txt; then
        echo "  ✅ IP encontrado no feed malicious-ips.txt"
    fi
    
    # Gerar tráfego para este IP
    echo "  🔄 Gerando tráfego para $test_ip..."
    nslookup google.com $test_ip >/dev/null 2>&1
    ping -c 1 $test_ip >/dev/null 2>&1
    
    # Aguardar processamento
    sleep 5
    
    # Verificar se houve detecção
    echo "  📊 Verificando detecções..."
    recent_intel=$(sudo docker-compose exec -T zeek tail -5 "/usr/local/zeek/logs/current/notice.log" | grep "Intelligence::" | wc -l)
    
    if [ "$recent_intel" -gt 0 ]; then
        echo "  🎉 SUCESSO: Intelligence Framework detectou!"
        sudo docker-compose exec -T zeek tail -5 "/usr/local/zeek/logs/current/notice.log" | grep "Intelligence::"
    else
        echo "  ⚠️  Nenhuma detecção do Intelligence Framework ainda"
    fi
else
    echo "❌ Nenhum IP de teste encontrado nos feeds"
fi

echo ""
echo "5️⃣ VERIFICANDO LOGS ESPECÍFICOS DO INTELLIGENCE"
echo "----------------------------------------------"

# Verificar se existe intel.log
if sudo docker-compose exec -T zeek test -f "/usr/local/zeek/logs/current/intel.log"; then
    echo "✅ Arquivo intel.log encontrado!"
    intel_entries=$(sudo docker-compose exec -T zeek wc -l "/usr/local/zeek/logs/current/intel.log" | awk '{print $1}')
    echo "📊 Entradas no intel.log: $intel_entries"
    
    if [ "$intel_entries" -gt 1 ]; then
        echo "🎯 Últimas detecções no intel.log:"
        sudo docker-compose exec -T zeek tail -5 "/usr/local/zeek/logs/current/intel.log"
    fi
else
    echo "⚠️  Arquivo intel.log não existe (indica que não houve matches ainda)"
fi

echo ""
echo "6️⃣ CONCLUSÃO"
echo "------------"

if [ "$intel_detections" -gt 0 ]; then
    echo "✅ Intelligence Framework está detectando ameaças!"
    echo "📊 Total de detecções de intelligence: $intel_detections"
else
    echo "⚠️  Intelligence Framework ainda não detectou ameaças"
    echo "📝 Isso pode acontecer porque:"
    echo "   • Não houve tráfego para IPs/domínios maliciosos"
    echo "   • Os feeds não estão carregados corretamente"
    echo "   • O tráfego gerado não foi capturado pelo Zeek"
fi

echo ""
echo "🔍 DIFERENÇA ENTRE OS SISTEMAS:"
echo "------------------------------"
echo "🚨 Port Scan Detector: Detecta comportamento suspeito (scans de porta)"
echo "🎯 Intelligence Framework: Detecta comunicação com IOCs conhecidos"
echo ""
echo "As detecções que você viu são do PORT SCAN DETECTOR, não do Intelligence!"

echo ""
echo "Para forçar teste do Intelligence Framework:"
echo "wget -q --timeout=5 http://malware.wicar.org/data/eicar_com.zip"
echo "curl -s http://malware-domain-from-feeds.com"
