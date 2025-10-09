#!/bin/bash

##############################################################################
# Teste Rápido de Detecção - SIMIR
# Faz consulta DNS e aguarda o alerta aparecer no log
##############################################################################

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

DOMAIN="${1:-example.com}"
WAIT_TIME=30

echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  TESTE DE DETECÇÃO - SIMIR${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo ""

echo -e "${YELLOW}⏱  Fazendo consulta DNS para: $DOMAIN${NC}"
START=$(date +%s)
nslookup "$DOMAIN" > /dev/null 2>&1

if [[ $? -ne 0 ]]; then
    echo -e "${NC}⚠  Consulta DNS falhou (mas pode ter sido capturada pelo Zeek)${NC}"
fi

echo -e "${YELLOW}⏳ Aguardando até ${WAIT_TIME}s para o alerta aparecer...${NC}"
echo ""

# Aguarda e verifica periodicamente
for i in $(seq 1 $WAIT_TIME); do
    sleep 1
    
    # Verifica se apareceu alerta novo
    NEW_ALERTS=$(tail -5 /home/rafael/SIMIR/logs/notice.log 2>/dev/null | grep -i "$DOMAIN" | wc -l)
    
    if [[ $NEW_ALERTS -gt 0 ]]; then
        ELAPSED=$(($(date +%s) - START))
        echo -e "${GREEN}✓ Alerta detectado após ${ELAPSED} segundos!${NC}"
        echo ""
        echo -e "${BLUE}Últimos alertas de $DOMAIN:${NC}"
        tail -10 /home/rafael/SIMIR/logs/notice.log | grep -i "$DOMAIN" | tail -3 | while IFS=$'\t' read -r ts rest; do
            TIME=$(date -d "@${ts%.*}" "+%H:%M:%S" 2>/dev/null || echo "$ts")
            MSG=$(echo "$rest" | awk -F'\t' '{print $11}')
            echo -e "  ${TIME} - ${MSG}"
        done
        exit 0
    fi
    
    # Mostra progresso
    if [[ $((i % 5)) -eq 0 ]]; then
        echo -e "  ${YELLOW}${i}s${NC} - Aguardando..."
    fi
done

echo ""
echo -e "${NC}⚠  Alerta não apareceu em ${WAIT_TIME} segundos${NC}"
echo -e "${NC}ℹ  Verifique:${NC}"
echo "  1. Se o domínio está nos feeds: grep '$DOMAIN' site/intel/*.txt"
echo "  2. Se o Zeek está rodando: docker exec SIMIR_Z zeekctl status"
echo "  3. Últimos alertas: tail -10 logs/notice.log | grep -v '^#'"
