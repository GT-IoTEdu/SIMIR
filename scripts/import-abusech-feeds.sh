#!/bin/bash

# Script para importar feeds do Abuse.ch para o Intelligence Framework do SIMIR
# Este é um exemplo de como integrar feeds externos reais

INTEL_DIR="/home/rafael/SIMIR/site/intel"
TEMP_DIR="/tmp/simir_feeds"

echo "🔄 Importando feeds do Abuse.ch..."

# Criar diretório temporário
mkdir -p "$TEMP_DIR"

# Função para converter formato Abuse.ch para formato Zeek Intel
convert_abusech_ips() {
    local input_file="$1"
    local output_file="$2"
    local source="$3"
    
    echo "#fields	indicator	indicator_type	meta.source	meta.desc" > "$output_file"
    
    # Remove comentários e linhas vazias, converte para formato Zeek
    grep -v "^#\|^$" "$input_file" | while read ip; do
        if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo -e "$ip\tIntel::ADDR\t$source\tIP malicioso - Abuse.ch" >> "$output_file"
        fi
    done
}

# Função para converter domínios URLhaus
convert_urlhaus_domains() {
    local input_file="$1"
    local output_file="$2"
    
    echo "#fields	indicator	indicator_type	meta.source	meta.desc" > "$output_file"
    
    # Extrai domínios do formato hosts file
    grep "^0\.0\.0\.0" "$input_file" | cut -f2 | while read domain; do
        if [[ "$domain" != "localhost" && "$domain" != "" ]]; then
            echo -e "$domain\tIntel::DOMAIN\tURLhaus\tDomínio malicioso - URLhaus" >> "$output_file"
        fi
    done
}

echo "📥 Baixando feed de IPs maliciosos (Feodo Tracker)..."
if curl -s --connect-timeout 10 "https://feodotracker.abuse.ch/downloads/ipblocklist.txt" -o "$TEMP_DIR/feodo_ips.txt"; then
    if [ -s "$TEMP_DIR/feodo_ips.txt" ]; then
        convert_abusech_ips "$TEMP_DIR/feodo_ips.txt" "$INTEL_DIR/feodo-ips.txt" "Feodo"
        echo "  ✅ Feed de IPs Feodo importado ($(wc -l < "$INTEL_DIR/feodo-ips.txt") entradas)"
    else
        echo "  ❌ Arquivo vazio recebido"
    fi
else
    echo "  ❌ Falha no download - usando feed de exemplo"
fi

echo "📥 Baixando feed de domínios maliciosos (URLhaus)..."
if curl -s --connect-timeout 10 "https://urlhaus.abuse.ch/downloads/hostfile/" -o "$TEMP_DIR/urlhaus_domains.txt"; then
    if [ -s "$TEMP_DIR/urlhaus_domains.txt" ]; then
        convert_urlhaus_domains "$TEMP_DIR/urlhaus_domains.txt" "$INTEL_DIR/urlhaus-domains.txt"
        echo "  ✅ Feed de domínios URLhaus importado ($(wc -l < "$INTEL_DIR/urlhaus-domains.txt") entradas)"
    else
        echo "  ❌ Arquivo vazio recebido"
    fi
else
    echo "  ❌ Falha no download - usando feed de exemplo"
fi

# Atualizar configuração do Zeek para incluir novos feeds
echo "🔧 Atualizando configuração do Zeek..."
if ! grep -q "feodo-ips.txt" /home/rafael/SIMIR/site/intelligence-framework.zeek; then
    sed -i '/malicious-ips\.txt"/a\    "/usr/local/zeek/share/zeek/site/intel/feodo-ips.txt",' \
        /home/rafael/SIMIR/site/intelligence-framework.zeek
fi

if ! grep -q "urlhaus-domains.txt" /home/rafael/SIMIR/site/intelligence-framework.zeek; then
    sed -i '/malicious-domains\.txt"/a\    "/usr/local/zeek/share/zeek/site/intel/urlhaus-domains.txt",' \
        /home/rafael/SIMIR/site/intelligence-framework.zeek
fi

# Limpeza
rm -rf "$TEMP_DIR"

echo "🔄 Reiniciando Zeek para carregar novos feeds..."

# Função para detectar se precisa de sudo
check_docker_permissions() {
    if docker ps >/dev/null 2>&1; then
        return 0  # Não precisa sudo
    else
        return 1  # Precisa sudo
    fi
}

if command -v docker-compose &> /dev/null; then
    if check_docker_permissions; then
        docker-compose restart SIMIR_Z 2>/dev/null || echo "⚠️  Execute manualmente: docker-compose restart SIMIR_Z"
    else
        echo "    ℹ️  Usando sudo para acessar Docker"
        sudo docker-compose restart SIMIR_Z 2>/dev/null || echo "⚠️  Execute manualmente: sudo docker-compose restart SIMIR_Z"
    fi
else
    echo "⚠️  Execute manualmente: [sudo] docker-compose restart SIMIR_Z"
fi

echo "✅ Importação de feeds do Abuse.ch concluída!"
echo ""
echo "📊 Resumo dos feeds importados:"
ls -la "$INTEL_DIR"/*.txt | grep -E "(feodo|urlhaus)" || echo "Nenhum feed externo importado (usando apenas feeds de exemplo)"
echo ""
echo "🧪 Para testar:"
echo "   ./scripts/test-intelligence.sh"
