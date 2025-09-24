#!/bin/bash

# Script para testar o Intelligence Framework do SIMIR
# Este script simula atividades que devem ser detectadas pelos feeds de inteligência

echo "🔍 Iniciando teste do Intelligence Framework..."

# Teste 1: Tentativa de conexão para IP malicioso
echo "📡 Teste 1: Tentativa de conexão para IP suspeito..."
timeout 2 nc -zv 192.168.100.100 80 2>/dev/null || true
timeout 2 nc -zv 10.0.0.100 443 2>/dev/null || true

# Teste 2: Consulta DNS para domínio malicioso
echo "🌐 Teste 2: Consulta DNS para domínios suspeitos..."
nslookup malware.example.com 8.8.8.8 2>/dev/null || true
nslookup phishing.example.org 8.8.8.8 2>/dev/null || true
nslookup botnet.bad.com 8.8.8.8 2>/dev/null || true

# Teste 3: Requisições HTTP com URLs maliciosas (simulação)
echo "🌍 Teste 3: Requisições HTTP com URLs suspeitas..."
timeout 2 curl -s "http://httpbin.org/get?url=/malware/download.exe" >/dev/null 2>&1 || true
timeout 2 curl -s "http://httpbin.org/get?url=/phishing/login.php" >/dev/null 2>&1 || true
timeout 2 curl -s "http://httpbin.org/get?url=/exploit/shell.php" >/dev/null 2>&1 || true

# Aguarda um pouco para o Zeek processar
echo "⏳ Aguardando processamento dos eventos (10 segundos)..."
sleep 10

echo "✅ Teste concluído!"
echo ""
echo "📊 Para verificar as detecções, execute:"
echo "   tail -f logs/notice_PortScan_BruteForce.log"
echo "   tail -f logs/current/intelligence.log"
echo "   tail -f logs/current/conn.log"
