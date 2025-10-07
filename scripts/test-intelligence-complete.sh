#!/bin/bash

echo "=============================================="
echo "  SCRIPT DE TESTE - INTELLIGENCE FRAMEWORK"
echo "=============================================="

echo ""
echo "1. Parando SIMIR..."
cd /home/rafael/SIMIR
./scripts/simir-control.sh stop >/dev/null 2>&1

echo ""
echo "2. Atualizando configuração..."
# Atualiza local.zeek para usar o framework final
sed -i 's/@load .*intelligence-framework.*/@load .\/intelligence-framework-final.zeek/' site/local.zeek

echo ""
echo "3. Verificando arquivo de feed de teste..."
if [ -f "site/intel/test-simple.txt" ]; then
    echo "   ✓ Arquivo existe:"
    cat site/intel/test-simple.txt
else 
    echo "   ✗ Criando arquivo de teste..."
    echo "#fields	indicator	indicator_type	meta.source	meta.desc" > site/intel/test-simple.txt
    echo "8.8.8.8	Intel::ADDR	TEST	IP de teste Google DNS" >> site/intel/test-simple.txt
fi

echo ""
echo "4. Iniciando SIMIR..."
./scripts/simir-control.sh start

echo ""
echo "5. Aguardando inicialização..."
sleep 10

echo ""
echo "6. Verificando se Zeek está rodando..."
if docker ps | grep -q "SIMIR_Z"; then
    echo "   ✓ Container Zeek está rodando"
else
    echo "   ✗ Container Zeek não está rodando"
    exit 1
fi

echo ""
echo "7. Verificando mensagens de inicialização..."
docker exec SIMIR_Z grep -i "SIMIR Intelligence" /usr/local/zeek/spool/zeek/stderr.log 2>/dev/null || echo "   Mensagens não encontradas no stderr"

echo ""
echo "8. Gerando tráfego de teste..."
echo "   Conectando ao 8.8.8.8 (que está no feed de teste)..."
timeout 3 nc -zv 8.8.8.8 53 >/dev/null 2>&1 || timeout 2 ping -c 1 8.8.8.8 >/dev/null 2>&1

echo ""
echo "9. Aguardando processamento..."
sleep 5

echo ""
echo "10. Verificando logs gerados..."
echo ""
echo "=== LOGS DE NOTICE ==="
docker exec SIMIR_Z find /usr/local/zeek/spool/zeek -name "*notice*" -type f -exec ls -la {} \;
docker exec SIMIR_Z find /usr/local/zeek/spool/zeek -name "*notice*" -type f -exec cat {} \; 2>/dev/null || echo "Nenhum arquivo notice encontrado"

echo ""
echo "=== LOGS DE INTELLIGENCE ==="
docker exec SIMIR_Z find /usr/local/zeek/spool/zeek -name "*intel*" -type f -exec ls -la {} \;

echo ""
echo "=== MENSAGENS DE DEBUG ==="
docker exec SIMIR_Z grep -i "intelligence\|intel.*match\|alerta.*gerado\|IOC carregado" /usr/local/zeek/spool/zeek/stderr.log 2>/dev/null || echo "Nenhuma mensagem de debug encontrada"

echo ""
echo "=== CONEXÕES RECENTES PARA 8.8.8.8 ==="
docker exec SIMIR_Z grep "8.8.8.8" /usr/local/zeek/spool/zeek/conn.log 2>/dev/null | tail -3 || echo "Nenhuma conexão encontrada"

echo ""
echo "=============================================="
echo "                 TESTE CONCLUÍDO"
echo "=============================================="