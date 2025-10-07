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
run_test "Sintaxe do ddos-detector.zeek" "docker exec SIMIR_Z zeek -parse-only /usr/local/zeek/share/zeek/site/ddos-detector.zeek > /dev/null 2>&1"

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
TEST_IOC_IP="1.1.1.1"      # IP real para gerar tráfego
TEST_IOC_DOMAIN="example.com"  # Domínio real para gerar tráfego DNS/HTTP
printf "#fields\tindicator\tindicator_type\tmeta.source\tmeta.desc\n%s\tIntel::ADDR\tTEST-IOC\tTeste automatizado do framework\n%s\tIntel::DOMAIN\tTEST-IOC\tTeste automatizado do framework\n" "$TEST_IOC_IP" "$TEST_IOC_DOMAIN" > /home/rafael/SIMIR/site/intel/test-auto.txt

log "IOC de teste criado: IP=$TEST_IOC_IP | Domínio=$TEST_IOC_DOMAIN"

# Contar notices antes do teste
NOTICE_COUNT_BEFORE=$(wc -l < /home/rafael/SIMIR/logs/notice.log 2>/dev/null || echo "0")
log "Notices antes do teste: $NOTICE_COUNT_BEFORE"

# Simular tráfego para o IOC (IP)
log "Simulando requisição HTTP para o IOC IP..."
timeout 5 curl -sI "http://$TEST_IOC_IP" > /dev/null 2>&1 || log "Requisição HTTP falhou (verifique conectividade)"

# Simular DNS e HTTP para o domínio IOC
log "Simulando consulta DNS para IOC domínio..."
nslookup "$TEST_IOC_DOMAIN" > /dev/null 2>&1 || log "Consulta DNS falhou"
log "Simulando requisição HTTP para IOC domínio..."
timeout 5 curl -sI "http://$TEST_IOC_DOMAIN" > /dev/null 2>&1 || log "Requisição HTTP para domínio falhou"

log "Aguardando processamento pelo Zeek (12 segundos)..."
sleep 12

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

# 6. TESTE DETECÇÃO DE FORÇA BRUTA
echo ""
echo "=============================================================="
echo "6. TESTE DETECÇÃO DE FORÇA BRUTA"
echo "=============================================================="

BRUTE_ALERTS_BEFORE=$(grep -c "BruteForce::" /home/rafael/SIMIR/logs/notice.log 2>/dev/null)
BRUTE_ALERTS_BEFORE=${BRUTE_ALERTS_BEFORE:-0}

log "Simulando múltiplas falhas de autenticação HTTP (401)..."

BRUTE_ENDPOINT="http://httpbingo.org/status/401"
BRUTE_REQUESTS=12
BRUTE_SUCCESS=0

for i in $(seq 1 $BRUTE_REQUESTS); do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$BRUTE_ENDPOINT" || echo "000")
    if [ "$STATUS" = "401" ]; then
        BRUTE_SUCCESS=$((BRUTE_SUCCESS + 1))
    else
        log "Resposta inesperada na tentativa $i: HTTP $STATUS"
    fi
    sleep 0.2
done

if [ $BRUTE_SUCCESS -lt $BRUTE_REQUESTS ]; then
    warning "Nem todas as requisições retornaram 401 (sucesso: $BRUTE_SUCCESS/$BRUTE_REQUESTS)"
fi

sleep 6

BRUTE_ALERTS_AFTER=$(grep -c "BruteForce::" /home/rafael/SIMIR/logs/notice.log 2>/dev/null)
BRUTE_ALERTS_AFTER=${BRUTE_ALERTS_AFTER:-0}
NEW_BRUTE_ALERTS=$((BRUTE_ALERTS_AFTER - BRUTE_ALERTS_BEFORE))

((TOTAL_TESTS++))
if [ $NEW_BRUTE_ALERTS -gt 0 ]; then
    success "Detector de força bruta gerou alertas ($NEW_BRUTE_ALERTS novos)"
    ((PASSED_TESTS++))
else
    error "Detector de força bruta não gerou alertas durante o teste"
fi

# 7. TESTE DETECÇÃO DE DDoS/DoS
echo ""
echo "=============================================================="
echo "7. TESTE DETECÇÃO DE DDoS/DoS"
echo "=============================================================="

DDOS_ALERTS_BEFORE=$(grep -c "DoS_Attack_Detected\|DDoS_Attack_Detected" /home/rafael/SIMIR/logs/notice.log 2>/dev/null)
DDOS_ALERTS_BEFORE=${DDOS_ALERTS_BEFORE:-0}

log "Simulando tráfego em alto volume para testar detector de DoS/DDoS..."
if command -v nc >/dev/null 2>&1; then
    for i in {1..60}; do
        timeout 1 nc -z "$TEST_IOC_IP" 80 > /dev/null 2>&1 &
    done
    wait
else
    log "nc não encontrado - utilizando múltiplos requests HTTP como fallback"
    for i in {1..40}; do
        timeout 2 curl -s "http://$TEST_IOC_IP" > /dev/null 2>&1 &
    done
    wait
fi

sleep 6

DDOS_ALERTS_AFTER=$(grep -c "DoS_Attack_Detected\|DDoS_Attack_Detected" /home/rafael/SIMIR/logs/notice.log 2>/dev/null)
DDOS_ALERTS_AFTER=${DDOS_ALERTS_AFTER:-0}
NEW_DDOS_ALERTS=$((DDOS_ALERTS_AFTER - DDOS_ALERTS_BEFORE))

((TOTAL_TESTS++))
if [ $NEW_DDOS_ALERTS -gt 0 ]; then
    success "Detector DDoS/DoS emitiu alertas ($NEW_DDOS_ALERTS novos)"
    ((PASSED_TESTS++))
else
    error "Detector DDoS/DoS não gerou alertas durante o teste"
fi

# 8. VALIDAÇÃO DOS LOGS E ARQUIVOS
echo ""
echo "=============================================================="
echo "8. VALIDAÇÃO DOS LOGS E ARQUIVOS"
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

# 9. ANÁLISE DETALHADA DO NOTICE.LOG
echo ""
echo "=============================================================="
echo "9. ANÁLISE DETALHADA DO NOTICE.LOG"
echo "=============================================================="

log "Analisando conteúdo atual do notice.log..."

echo ""
echo "--- MENSAGENS DE NOTICE ATUAIS ---"
if [ -f /home/rafael/SIMIR/logs/notice.log ]; then
    # Mostrar tipos de notices
    cat /home/rafael/SIMIR/logs/notice.log | jq -r '.note + " " + .msg' 2>/dev/null | tail -10 || \
    grep -o '"note":"[^\"]*"' /home/rafael/SIMIR/logs/notice.log | sort | uniq -c | head -10 2>/dev/null || \
    echo "Arquivo notice.log existe mas formato pode estar inconsistente"
else
    echo "Arquivo notice.log não encontrado"
fi

# 10. RESUMO FINAL
echo ""
echo "=============================================================="
echo "10. RESUMO FINAL"
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
printf "#fields\tindicator\tindicator_type\tmeta.source\tmeta.desc\n" > /home/rafael/SIMIR/site/intel/test-auto.txt

exit $EXIT_CODE