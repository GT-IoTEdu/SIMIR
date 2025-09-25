#!/bin/bash

echo "🧪 Teste direto do Intelligence Framework"
echo "Fazendo ping para IP conhecido nos feeds..."

# Força tráfego TCP para o IP que sabemos estar nos feeds
timeout 2 telnet 8.8.8.8 80 2>/dev/null || true
timeout 2 nc -zv 8.8.8.8 443 2>/dev/null || true

echo "Aguardando 5 segundos..."
sleep 5

echo "Verificando logs..."
echo "== NOTICE LOG =="
tail -3 /home/rafael/SIMIR/logs/notice.log

echo ""
echo "== CONNECTIONS para 8.8.8.8 =="
sudo docker exec SIMIR_Z grep "8.8.8.8" /usr/local/zeek/spool/zeek/conn.log | tail -3 || echo "Nenhuma conexão encontrada"

echo ""
echo "== DEBUG MESSAGES =="
sudo docker exec SIMIR_Z grep -i "intelligence\|match" /usr/local/zeek/spool/zeek/stdout.log 2>/dev/null || echo "Nenhuma mensagem de debug"
