#!/bin/bash

##############################################################################
# Monitor de Alertas em Tempo Real - SIMIR
# Mostra alertas do Zeek com formatação colorida
##############################################################################

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

NOTICE_LOG="/home/rafael/SIMIR/logs/notice.log"

if [[ ! -f "$NOTICE_LOG" ]]; then
    echo -e "${RED}✗ Arquivo $NOTICE_LOG não encontrado${NC}"
    exit 1
fi

echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  MONITOR DE ALERTAS SIMIR - TEMPO REAL${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${YELLOW}⚠  NOTA: Alertas aparecem com delay de 5-30 segundos devido ao buffer do Zeek${NC}"
echo -e "${YELLOW}Pressione Ctrl+C para sair${NC}"
echo ""

# Função para formatar timestamp
format_time() {
    local ts=$1
    local sec=${ts%.*}
    date -d "@$sec" "+%H:%M:%S" 2>/dev/null || echo "$ts"
}

# Função para colorir alertas por tipo
colorize_alert() {
    local line="$1"
    local timestamp=$(echo "$line" | awk '{print $1}')
    local formatted_time=$(format_time "$timestamp")
    
    if [[ "$line" =~ "THREAT-INTEL" ]] || [[ "$line" =~ "Malicious" ]]; then
        echo -e "${formatted_time} ${MAGENTA}[INTEL]${NC} $(echo "$line" | grep -oP '\[THREAT-INTEL\].*' | sed 's/\[THREAT-INTEL\]//')"
    elif [[ "$line" =~ "PORT-SCAN" ]] || [[ "$line" =~ "PortScan" ]]; then
        echo -e "${formatted_time} ${YELLOW}[PORTSCAN]${NC} $(echo "$line" | grep -oP '\[PORT-SCAN\].*' | sed 's/\[PORT-SCAN\]//')"
    elif [[ "$line" =~ "BRUTE-FORCE" ]] || [[ "$line" =~ "BruteForce" ]]; then
        echo -e "${formatted_time} ${RED}[BRUTE-FORCE]${NC} $(echo "$line" | grep -oP '\[BRUTE-FORCE\].*' | sed 's/\[BRUTE-FORCE\]//')"
    elif [[ "$line" =~ "DDOS" ]] || [[ "$line" =~ "DOS" ]] || [[ "$line" =~ "DoS" ]]; then
        echo -e "${formatted_time} ${RED}[DDOS]${NC} $(echo "$line" | grep -oP '\[DD?OS\].*' | sed 's/\[DD?OS\]//')"
    elif [[ "$line" =~ "SYSTEM" ]] || [[ "$line" =~ "Intel_Framework" ]]; then
        echo -e "${formatted_time} ${GREEN}[SYSTEM]${NC} $(echo "$line" | grep -oP '\[SYSTEM\].*' | sed 's/\[SYSTEM\]//')"
    else
        echo -e "${formatted_time} ${BLUE}[ALERT]${NC} $line"
    fi
}

# Pula cabeçalhos
tail -n +1 -f "$NOTICE_LOG" | while IFS= read -r line; do
    # Ignora linhas de comentário/header
    if [[ "$line" =~ ^# ]]; then
        continue
    fi
    
    # Ignora linhas vazias
    if [[ -z "$line" ]]; then
        continue
    fi
    
    # Formata e exibe
    colorize_alert "$line"
done
