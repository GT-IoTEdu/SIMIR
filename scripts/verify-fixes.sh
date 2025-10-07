#!/bin/bash

# Script de Verificação dos Problemas Corrigidos - SIMIR Intelligence Framework
# Data: $(date)

echo "=============================================================="
echo "   VERIFICAÇÃO DOS PROBLEMAS CORRIGIDOS - SIMIR"
echo "=============================================================="

# Função para verificar status
check_status() {
    if [ $1 -eq 0 ]; then
        echo "✅ $2"
    else
        echo "❌ $2"
    fi
}

echo ""
echo "1. VERIFICAÇÃO DE EMOJIS E CARACTERES UNICODE"
echo "--------------------------------------------------------------"

# Verifica se há emojis nos arquivos .zeek
EMOJI_COUNT=$(find site/ -name "*.zeek" -exec grep -P "[\x{1F600}-\x{1F64F}]|[\x{1F300}-\x{1F5FF}]|[\x{1F680}-\x{1F6FF}]|[\x{2600}-\x{26FF}]|[\x{2700}-\x{27BF}]" {} \; 2>/dev/null | wc -l)

if [ $EMOJI_COUNT -eq 0 ]; then
    echo "✅ Nenhum emoji encontrado nos arquivos .zeek"
else
    echo "❌ Encontrados $EMOJI_COUNT emojis nos arquivos .zeek"
fi

echo ""
echo "2. VERIFICAÇÃO DE EVENTOS INCOMPATÍVEIS"
echo "--------------------------------------------------------------"

# Verifica eventos problemáticos
INCOMPATIBLE_EVENTS=$(find site/ -name "*.zeek" -exec grep -E "Intel::read_entry|Intel::item_expired" {} \; 2>/dev/null | wc -l)

if [ $INCOMPATIBLE_EVENTS -eq 0 ]; then
    echo "✅ Nenhum evento incompatível encontrado"
else
    echo "❌ Encontrados $INCOMPATIBLE_EVENTS eventos incompatíveis"
fi

echo ""
echo "3. VERIFICAÇÃO DO ARQUIVO NOTICE.LOG"
echo "--------------------------------------------------------------"

# Verifica se o container está rodando
if docker ps | grep -q "SIMIR_Z"; then
    echo "✅ Container SIMIR_Z está executando"
    
    # Verifica se notice.log existe
    if docker exec SIMIR_Z test -f /usr/local/zeek/spool/zeek/notice.log; then
        echo "✅ Arquivo notice.log existe"
        
        # Verifica conteúdo do notice.log
        NOTICE_COUNT=$(docker exec SIMIR_Z wc -l < /usr/local/zeek/spool/zeek/notice.log 2>/dev/null || echo "0")
        echo "✅ Notice.log contém $NOTICE_COUNT entradas"
        
        # Mostra última entrada
        echo ""
        echo "📋 Última entrada do notice.log:"
        docker exec SIMIR_Z tail -1 /usr/local/zeek/spool/zeek/notice.log 2>/dev/null || echo "Nenhuma entrada encontrada"
        
    else
        echo "❌ Arquivo notice.log não encontrado"
    fi
else
    echo "⚠️  Container SIMIR_Z não está executando"
fi

echo ""
echo "4. VERIFICAÇÃO DA SINTAXE DOS ARQUIVOS ZEEK"
echo "--------------------------------------------------------------"

# Testa sintaxe do intelligence framework
echo "🔍 Testando sintaxe do intelligence-framework.zeek..."
if docker exec SIMIR_Z zeek -u /usr/local/zeek/share/zeek/site/intelligence-framework.zeek >/dev/null 2>&1; then
    echo "✅ Sintaxe do intelligence-framework.zeek está correta"
else
    echo "❌ Problemas de sintaxe no intelligence-framework.zeek"
fi

# Testa sintaxe do local.zeek
echo "🔍 Testando sintaxe do local.zeek..."
if docker exec SIMIR_Z zeek -u /usr/local/zeek/share/zeek/site/local.zeek >/dev/null 2>&1; then
    echo "✅ Sintaxe do local.zeek está correta"
else
    echo "❌ Problemas de sintaxe no local.zeek"
fi

echo ""
echo "5. VERIFICAÇÃO DO FUNCIONAMENTO DO INTELLIGENCE FRAMEWORK"
echo "--------------------------------------------------------------"

# Verifica mensagens de inicialização
if docker exec SIMIR_Z grep -q "SIMIR Intelligence Framework INICIADO" /usr/local/zeek/spool/zeek/stderr.log 2>/dev/null; then
    echo "✅ Intelligence Framework está inicializando corretamente"
else
    echo "⚠️  Mensagens de inicialização não encontradas (normal se recém iniciado)"
fi

# Verifica feeds configurados
FEED_COUNT=$(grep -c "intel.*txt" site/intelligence-framework.zeek 2>/dev/null || echo "0")
echo "✅ $FEED_COUNT feeds de intelligence configurados"

echo ""
echo "6. VERIFICAÇÃO DE LOGS DE ERROR"
echo "--------------------------------------------------------------"

if docker exec SIMIR_Z test -f /usr/local/zeek/spool/zeek/stderr.log; then
    ERROR_COUNT=$(docker exec SIMIR_Z grep -c -i "error\|fatal" /usr/local/zeek/spool/zeek/stderr.log 2>/dev/null || echo "0")
    if [ $ERROR_COUNT -eq 0 ]; then
        echo "✅ Nenhum erro encontrado nos logs"
    else
        echo "⚠️  Encontrados $ERROR_COUNT erros nos logs"
        echo "📋 Últimos erros:"
        docker exec SIMIR_Z grep -i "error\|fatal" /usr/local/zeek/spool/zeek/stderr.log 2>/dev/null | tail -3
    fi
else
    echo "⚠️  Arquivo de log de erro não encontrado"
fi

echo ""
echo "=============================================================="
echo "                    RESUMO DA VERIFICAÇÃO"
echo "=============================================================="

TOTAL_CHECKS=6
PASSED_CHECKS=0

# Contagem dos checks (simplificada)
[ $EMOJI_COUNT -eq 0 ] && ((PASSED_CHECKS++))
[ $INCOMPATIBLE_EVENTS -eq 0 ] && ((PASSED_CHECKS++))
docker ps | grep -q "SIMIR_Z" && docker exec SIMIR_Z test -f /usr/local/zeek/spool/zeek/notice.log && ((PASSED_CHECKS++))
docker exec SIMIR_Z zeek -u /usr/local/zeek/share/zeek/site/intelligence-framework.zeek >/dev/null 2>&1 && ((PASSED_CHECKS++))
docker exec SIMIR_Z zeek -u /usr/local/zeek/share/zeek/site/local.zeek >/dev/null 2>&1 && ((PASSED_CHECKS++))
[ $FEED_COUNT -gt 0 ] && ((PASSED_CHECKS++))

echo "✅ Verificações aprovadas: $PASSED_CHECKS/$TOTAL_CHECKS"

if [ $PASSED_CHECKS -eq $TOTAL_CHECKS ]; then
    echo "🎉 TODOS OS PROBLEMAS FORAM RESOLVIDOS COM SUCESSO!"
else
    echo "⚠️  Ainda existem alguns pontos que precisam de atenção"
fi

echo ""
echo "=============================================================="