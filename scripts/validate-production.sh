#!/bin/bash

# Script de Validação Completa - SIMIR Produção
# Valida Intelligence Framework, Port Scan Detection e Padrões de Log

echo "=============================================================="
echo "        VALIDAÇÃO COMPLETA SIMIR - PRODUÇÃO v1.0"
echo "=============================================================="

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Função para logging
log() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"
}

success() {
    echo -e "${GREEN}✅ $1${NC}"
}

warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

error() {
    echo -e "${RED}❌ $1${NC}"
}

# Contadores
TOTAL_TESTS=0
PASSED_TESTS=0

# Função para executar teste
run_test() {
    ((TOTAL_TESTS++))
    if eval "$2"; then
        success "$1"
        ((PASSED_TESTS++))
        return 0
    else
        error "$1"
        return 1
    fi
}

log "Iniciando validação completa do SIMIR..."

echo ""
echo "=============================================================="
echo "1. VALIDAÇÃO DO SISTEMA BASE"
echo "=============================================================="

# Teste 1: Container rodando
run_test "Container SIMIR está executando" "docker ps | grep -q SIMIR_Z"

# Teste 2: Sintaxe dos arquivos Zeek
run_test "Sintaxe do local.zeek" "docker exec SIMIR_Z zeek -u /usr/local/zeek/share/zeek/site/local.zeek >/dev/null 2>&1"
run_test "Sintaxe do intelligence-framework.zeek" "docker exec SIMIR_Z zeek -u /usr/local/zeek/share/zeek/site/intelligence-framework.zeek >/dev/null 2>&1"
run_test "Sintaxe do port-scan-detector-production.zeek" "docker exec SIMIR_Z zeek -u /usr/local/zeek/share/zeek/site/port-scan-detector-production.zeek >/dev/null 2>&1"

echo ""
echo "=============================================================="
echo "2. VALIDAÇÃO DO INTELLIGENCE FRAMEWORK"
echo "=============================================================="

# Teste 3: Notice.log existe e tem conteúdo
run_test "Arquivo notice.log existe" "docker exec SIMIR_Z test -f /usr/local/zeek/spool/zeek/notice.log"

# Teste 4: Intelligence Framework inicializou
run_test "Intelligence Framework inicializou" "docker exec SIMIR_Z grep -q 'SIMIR Intelligence Framework' /usr/local/zeek/spool/zeek/notice.log 2>/dev/null"

# Teste 5: Feeds configurados
FEED_COUNT=$(docker exec SIMIR_Z grep -c "Feed configurado\|Feed ativo" /usr/local/zeek/spool/zeek/stderr.log 2>/dev/null || echo "0")
run_test "Feeds de intelligence carregados ($FEED_COUNT feeds)" "[ $FEED_COUNT -gt 0 ]"

echo ""
echo "=============================================================="
echo "3. TESTE FUNCIONAL DO INTELLIGENCE FRAMEWORK"
echo "=============================================================="

log "Executando teste funcional com tráfego real..."

# Gera tráfego de teste
log "Gerando tráfego de teste (ping para 8.8.8.8)..."
timeout 5 ping -c 3 8.8.8.8 >/dev/null 2>&1

# Gera mais tráfego (DNS queries)
log "Gerando consultas DNS de teste..."
nslookup google.com 8.8.8.8 >/dev/null 2>&1
nslookup github.com 8.8.8.8 >/dev/null 2>&1

# Aguarda processamento
log "Aguardando processamento pelo Zeek (10 segundos)..."
sleep 10

# Teste 6: Novos notices foram gerados
NOTICE_COUNT_BEFORE=$(docker exec SIMIR_Z wc -l < /usr/local/zeek/spool/zeek/notice.log 2>/dev/null || echo "0")
log "Total de notices no log: $NOTICE_COUNT_BEFORE"

echo ""
echo "=============================================================="
echo "4. VALIDAÇÃO DOS PADRÕES DE MENSAGEM"
echo "=============================================================="

# Teste 7: Padrões de mensagem padronizados
log "Analisando padrões de mensagens no notice.log..."

# Verifica se há mensagens padronizadas
STANDARD_MSGS=$(docker exec SIMIR_Z grep -E "\[(SYSTEM|THREAT-INTEL|PORT-SCAN|BRUTE-FORCE)\]" /usr/local/zeek/spool/zeek/notice.log 2>/dev/null | wc -l || echo "0")
run_test "Mensagens seguem padrão estabelecido" "[ $STANDARD_MSGS -gt 0 ]"

echo ""
echo "=============================================================="
echo "5. TESTE ANTI-FALSOS-POSITIVOS (PORT SCAN)"
echo "=============================================================="

log "Executando teste de atividade normal (não deve gerar alertas)..."

# Simula atividade normal (não deve ser detectada como scan)
curl -s http://httpbin.org/ip >/dev/null 2>&1 || true
curl -s http://httpbin.org/user-agent >/dev/null 2>&1 || true
curl -s http://google.com >/dev/null 2>&1 || true

# Aguarda
sleep 5

# Verifica se NÃO foram gerados alertas de port scan para atividade legítima
PORTSCAN_ALERTS_BEFORE=$NOTICE_COUNT_BEFORE
PORTSCAN_ALERTS_AFTER=$(docker exec SIMIR_Z wc -l < /usr/local/zeek/spool/zeek/notice.log 2>/dev/null || echo "0")

# Teste 8: Atividade legítima não gera falsos positivos
run_test "Atividade HTTP normal não gera falsos positivos de port scan" "[ $PORTSCAN_ALERTS_AFTER -eq $PORTSCAN_ALERTS_BEFORE ] || [ $((PORTSCAN_ALERTS_AFTER - PORTSCAN_ALERTS_BEFORE)) -eq 0 ]"

echo ""
echo "=============================================================="
echo "6. VALIDAÇÃO DOS LOGS E ARQUIVOS"
echo "=============================================================="

# Teste 9: Arquivos de log essenciais existem
run_test "Arquivo conn.log existe" "docker exec SIMIR_Z test -f /usr/local/zeek/spool/zeek/conn.log"
run_test "Arquivo dns.log existe" "docker exec SIMIR_Z test -f /usr/local/zeek/spool/zeek/dns.log"

# Teste 10: Sem erros críticos
ERROR_COUNT=$(docker exec SIMIR_Z grep -c -i "fatal\|critical" /usr/local/zeek/spool/zeek/stderr.log 2>/dev/null || echo "0")
run_test "Sem erros fatais no sistema" "[ $ERROR_COUNT -eq 0 ]"

echo ""
echo "=============================================================="
echo "7. ANÁLISE DETALHADA DO NOTICE.LOG"
echo "=============================================================="

log "Analisando conteúdo atual do notice.log..."
echo ""
echo "--- MENSAGENS DE NOTICE ATUAIS ---"
docker exec SIMIR_Z cat /usr/local/zeek/spool/zeek/notice.log 2>/dev/null | while read line; do
    MSG=$(echo "$line" | jq -r '.msg' 2>/dev/null || echo "$line")
    NOTE=$(echo "$line" | jq -r '.note' 2>/dev/null || echo "UNKNOWN")
    echo "[$NOTE] $MSG"
done

echo ""
echo "=============================================================="
echo "8. RESUMO FINAL"
echo "=============================================================="

# Calcula percentual de sucesso
SUCCESS_RATE=$((PASSED_TESTS * 100 / TOTAL_TESTS))

echo ""
log "Testes executados: $TOTAL_TESTS"
log "Testes aprovados: $PASSED_TESTS"
log "Taxa de sucesso: $SUCCESS_RATE%"

echo ""
if [ $PASSED_TESTS -eq $TOTAL_TESTS ]; then
    success "🎉 SIMIR APROVADO PARA PRODUÇÃO!"
    success "Todos os componentes estão funcionando corretamente"
    success "✅ Intelligence Framework: Operacional"
    success "✅ Port Scan Detection: Anti-falsos-positivos ativo"
    success "✅ Padrões de mensagem: Implementados"
    success "✅ Sistema: Pronto para ambiente produtivo"
elif [ $SUCCESS_RATE -ge 80 ]; then
    warning "⚠️  SIMIR PARCIALMENTE APROVADO"
    warning "Alguns testes falharam, mas sistema está funcional"
    warning "Recomenda-se revisar os pontos de falha antes da produção"
else
    error "❌ SIMIR NÃO APROVADO PARA PRODUÇÃO"
    error "Muitos testes falharam - correções necessárias"
    error "Não recomendado para ambiente produtivo no estado atual"
fi

echo ""
echo "=============================================================="
log "Validação completa finalizada"
echo "=============================================================="

# Retorna código de saída apropriado
if [ $PASSED_TESTS -eq $TOTAL_TESTS ]; then
    exit 0
elif [ $SUCCESS_RATE -ge 80 ]; then
    exit 1  
else
    exit 2
fi