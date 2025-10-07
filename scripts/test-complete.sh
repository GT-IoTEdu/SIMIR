#!/bin/bash

# Script de Teste Completo do SIMIR
# Corrigido para trabalhar com os caminhos corretos

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Função para logging
log() {
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# Funções de resultado
success() {
    echo -e "✅ $1"
}

error() {
    echo -e "❌ $1"
}

warning() {
    echo -e "⚠️  $1"
}

info() {
    echo -e "ℹ️  $1"
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

echo "=============================================================="
echo "        TESTE COMPLETO SIMIR - VERSÃO CORRIGIDA v1.1"
echo "=============================================================="
log "Iniciando teste completo do SIMIR..."

# 1. VALIDAÇÃO DO SISTEMA BASE
echo ""
echo "=============================================================="
echo "1. VALIDAÇÃO DO SISTEMA BASE"
echo "=============================================================="

run_test "Container SIMIR está executando" "docker ps | grep -q SIMIR_Z"
run_test "Sintaxe do local.zeek" "docker exec SIMIR_Z zeek -parse-only /usr/local/zeek/share/zeek/site/local.zeek > /dev/null 2>&1"
run_test "Sintaxe do intelligence-framework.zeek" "docker exec SIMIR_Z zeek -parse-only /usr/local/zeek/share/zeek/site/intelligence-framework.zeek > /dev/null 2>&1"
run_test "Sintaxe do port-scan-detector.zeek" "docker exec SIMIR_Z zeek -parse-only /usr/local/zeek/share/zeek/site/port-scan-detector.zeek > /dev/null 2>&1"

# 2. VALIDAÇÃO DO INTELLIGENCE FRAMEWORK
echo ""
echo "=============================================================="
echo "2. VALIDAÇÃO DO INTELLIGENCE FRAMEWORK"
echo "=============================================================="

run_test "Arquivo notice.log existe" "test -f /home/rafael/SIMIR/logs/notice.log"
run_test "Intelligence Framework inicializou" "grep -q 'Intelligence Framework' /home/rafael/SIMIR/logs/notice.log 2>/dev/null"

FEED_COUNT=$(ls /home/rafael/SIMIR/site/intel/*.txt 2>/dev/null | wc -l)
run_test "Feeds de intelligence carregados ($FEED_COUNT feeds)" "[ $FEED_COUNT -gt 0 ]"

# 3. TESTE FUNCIONAL DO INTELLIGENCE FRAMEWORK
echo ""
echo "=============================================================="
echo "3. TESTE FUNCIONAL DO INTELLIGENCE FRAMEWORK"
echo "=============================================================="

log "Executando teste funcional com IOC conhecido..."

# Criar um IOC de teste conhecido
TEST_IOC_IP="198.51.100.100"  # IP de documentação RFC
printf "# IOC de Teste\n$TEST_IOC_IP\tIntel::ADDR\tTEST-IOC\tTeste automatizado do framework\n" > /home/rafael/SIMIR/site/intel/test-auto.txt

log "IOC de teste criado: $TEST_IOC_IP"

# Contar notices antes do teste
NOTICE_COUNT_BEFORE=$(wc -l < /home/rafael/SIMIR/logs/notice.log 2>/dev/null || echo "0")
log "Notices antes do teste: $NOTICE_COUNT_BEFORE"

# Simular tráfego para o IOC
log "Tentando ping no IOC de teste..."
timeout 5 ping -c 2 $TEST_IOC_IP > /dev/null 2>&1 || log "Ping falhou (esperado se IP não responde)"

# Simular DNS lookup
log "Simulando consulta DNS..."
nslookup google.com > /dev/null 2>&1

log "Aguardando processamento pelo Zeek (10 segundos)..."
sleep 10

# Contar notices após teste
NOTICE_COUNT_AFTER=$(wc -l < /home/rafael/SIMIR/logs/notice.log 2>/dev/null || echo "0")
NEW_NOTICES=$((NOTICE_COUNT_AFTER - NOTICE_COUNT_BEFORE))

log "Notices após teste: $NOTICE_COUNT_AFTER (novos: $NEW_NOTICES)"

if [ $NEW_NOTICES -gt 0 ]; then
    success "Framework detectou atividade ($NEW_NOTICES novos notices)"
else
    warning "Framework não gerou novos notices durante teste"
fi

# 4. VALIDAÇÃO DOS PADRÕES DE MENSAGEM
echo ""
echo "=============================================================="
echo "4. VALIDAÇÃO DOS PADRÕES DE MENSAGEM"
echo "=============================================================="

log "Analisando padrões de mensagens no notice.log..."
STANDARD_MSGS=$(grep -E "\[(SYSTEM|THREAT-INTEL|PORT-SCAN|BRUTE-FORCE|Intel_Framework_Ready|PortScan::)\]" /home/rafael/SIMIR/logs/notice.log 2>/dev/null | wc -l || echo "0")

if [ $STANDARD_MSGS -gt 0 ]; then
    success "Mensagens seguem padrão estabelecido ($STANDARD_MSGS mensagens padronizadas)"
    ((TOTAL_TESTS++))
    ((PASSED_TESTS++))
else
    error "Nenhuma mensagem padronizada encontrada"
    ((TOTAL_TESTS++))
fi

# 5. TESTE ANTI-FALSOS-POSITIVOS (PORT SCAN)
echo ""
echo "=============================================================="
echo "5. TESTE ANTI-FALSOS-POSITIVOS (PORT SCAN)"
echo "=============================================================="

log "Executando teste de atividade normal (não deve gerar muitos alertas de port scan)..."

PORTSCAN_ALERTS_BEFORE=$(grep -c "PortScan::" /home/rafael/SIMIR/logs/notice.log 2>/dev/null)
PORTSCAN_ALERTS_BEFORE=${PORTSCAN_ALERTS_BEFORE:-0}

# Simular atividade normal (algumas conexões HTTP)
log "Simulando atividade HTTP normal..."
curl -s http://httpbin.org/get > /dev/null 2>&1 || log "Conexão HTTP teste falhou"
curl -s http://www.google.com > /dev/null 2>&1 || log "Conexão Google falhou"

sleep 5

PORTSCAN_ALERTS_AFTER=$(grep -c "PortScan::" /home/rafael/SIMIR/logs/notice.log 2>/dev/null)
PORTSCAN_ALERTS_AFTER=${PORTSCAN_ALERTS_AFTER:-0}
NEW_PORTSCAN_ALERTS=$((PORTSCAN_ALERTS_AFTER - PORTSCAN_ALERTS_BEFORE))

if [ $NEW_PORTSCAN_ALERTS -le 2 ]; then
    success "Atividade HTTP normal não gera falsos positivos excessivos ($NEW_PORTSCAN_ALERTS novos alertas)"
    ((TOTAL_TESTS++))
    ((PASSED_TESTS++))
else
    warning "Muitos alertas de port scan para atividade normal ($NEW_PORTSCAN_ALERTS novos)"
    ((TOTAL_TESTS++))
fi

# 6. VALIDAÇÃO DOS LOGS E ARQUIVOS
echo ""
echo "=============================================================="
echo "6. VALIDAÇÃO DOS LOGS E ARQUIVOS"
echo "=============================================================="

run_test "Arquivo conn.log existe" "test -f /home/rafael/SIMIR/logs/conn.log"
run_test "Arquivo dns.log existe" "test -f /home/rafael/SIMIR/logs/dns.log"

# Verificar se há erros críticos no sistema
FATAL_ERRORS=$(docker logs SIMIR_Z 2>&1 | grep -i "fatal\|critical\|abort" | wc -l)
if [ $FATAL_ERRORS -eq 0 ]; then
    success "Sem erros fatais no sistema"
    ((TOTAL_TESTS++))
    ((PASSED_TESTS++))
else
    error "Erros fatais encontrados no sistema ($FATAL_ERRORS erros)"
    ((TOTAL_TESTS++))
fi

# 7. ANÁLISE DETALHADA DO NOTICE.LOG
echo ""
echo "=============================================================="
echo "7. ANÁLISE DETALHADA DO NOTICE.LOG"
echo "=============================================================="

log "Analisando conteúdo atual do notice.log..."

echo ""
echo "--- MENSAGENS DE NOTICE ATUAIS ---"
if [ -f /home/rafael/SIMIR/logs/notice.log ]; then
    # Mostrar tipos de notices
    cat /home/rafael/SIMIR/logs/notice.log | jq -r '.note + " " + .msg' 2>/dev/null | tail -10 || \
    grep -o '"note":"[^"]*"' /home/rafael/SIMIR/logs/notice.log | sort | uniq -c | head -10 2>/dev/null || \
    echo "Arquivo notice.log existe mas formato pode estar inconsistente"
else
    echo "Arquivo notice.log não encontrado"
fi

# 8. RESUMO FINAL
echo ""
echo "=============================================================="
echo "8. RESUMO FINAL"
echo "=============================================================="

echo ""
log "Testes executados: $TOTAL_TESTS"
log "Testes aprovados: $PASSED_TESTS"

if [ $TOTAL_TESTS -gt 0 ]; then
    SUCCESS_RATE=$(( (PASSED_TESTS * 100) / TOTAL_TESTS ))
    log "Taxa de sucesso: ${SUCCESS_RATE}%"
    
    if [ $SUCCESS_RATE -ge 85 ]; then
        echo ""
        success "✅ SIMIR APROVADO PARA PRODUÇÃO"
        success "Taxa de sucesso aceitável para ambiente produtivo"
        success "Sistema está funcionando dentro dos parâmetros esperados"
        EXIT_CODE=0
    elif [ $SUCCESS_RATE -ge 70 ]; then
        echo ""
        warning "⚠️  SIMIR PARCIALMENTE APROVADO"
        warning "Alguns testes falharam, mas sistema está funcional"
        warning "Recomenda-se revisar os pontos de falha antes da produção"
        EXIT_CODE=1
    else
        echo ""
        error "❌ SIMIR NÃO APROVADO PARA PRODUÇÃO"
        error "Muitos testes falharam - correções necessárias"
        error "Não recomendado para ambiente produtivo no estado atual"
        EXIT_CODE=2
    fi
else
    error "❌ Nenhum teste foi executado"
    EXIT_CODE=3
fi

echo ""
echo "=============================================================="
log "Teste completo finalizado"
echo "=============================================================="

# Limpeza
rm -f /home/rafael/SIMIR/site/intel/test-auto.txt

exit $EXIT_CODE