#!/bin/bash

# Script para validar a estrutura do projeto SIMIR

echo "=== Validação da Estrutura do Projeto SIMIR ==="
echo

# Verifica se estamos no diretório correto
if [ ! -f "docker-compose.yml" ]; then
    echo "❌ ERRO: Execute este script a partir da raiz do projeto SIMIR"
    exit 1
fi

echo "✓ Executando a partir do diretório correto"

# Verifica arquivos principais
files_to_check=(
    "docker-compose.yml"
    "Dockerfile"
    "README.md"
    "run-test.sh"
    "dev.sh"
)

echo
echo "Verificando arquivos principais..."
for file in "${files_to_check[@]}"; do
    if [ -f "$file" ] || [ -L "$file" ]; then
        echo "✓ $file"
    else
        echo "❌ $file - AUSENTE"
    fi
done

# Verifica scripts
scripts_to_check=(
    "scripts/entrypoint.sh"
    "scripts/check-interface.sh"
    "scripts/setup-permissions.sh"
    "scripts/test-container.sh"
    "scripts/dev.sh"
    "scripts/README.md"
)

echo
echo "Verificando scripts..."
for script in "${scripts_to_check[@]}"; do
    if [ -f "$script" ]; then
        if [ -x "$script" ] || [[ "$script" == *.md ]]; then
            echo "✓ $script"
        else
            echo "⚠ $script - SEM PERMISSÃO DE EXECUÇÃO"
        fi
    else
        echo "❌ $script - AUSENTE"
    fi
done

# Verifica diretórios
dirs_to_check=(
    "scripts"
    "site"
    "etc"
    "logs"
    "docs"
)

echo
echo "Verificando diretórios..."
for dir in "${dirs_to_check[@]}"; do
    if [ -d "$dir" ]; then
        echo "✓ $dir/"
    else
        echo "❌ $dir/ - AUSENTE"
    fi
done

# Verifica se o Docker está funcionando
echo
echo "Verificando Docker..."
if command -v docker >/dev/null 2>&1; then
    if docker ps >/dev/null 2>&1; then
        echo "✓ Docker está funcionando"
    else
        echo "⚠ Docker instalado mas sem permissão ou não rodando"
    fi
else
    echo "❌ Docker não encontrado"
fi

# Verifica se docker-compose está funcionando
if command -v docker-compose >/dev/null 2>&1; then
    echo "✓ Docker Compose (standalone) disponível"
elif docker compose version >/dev/null 2>&1; then
    echo "✓ Docker Compose (integrado) disponível"
else
    echo "⚠ Docker Compose não encontrado"
fi

echo
echo "=== Comandos disponíveis ==="
echo "• ./run-test.sh           - Teste completo do container"
echo "• ./dev.sh help           - Ver todos os comandos de desenvolvimento"
echo "• ./dev.sh build          - Construir imagem"
echo "• ./dev.sh start          - Iniciar container"
echo "• ./dev.sh logs-f         - Acompanhar logs"
echo "• ./scripts/test-container.sh  - Teste direto"

echo
echo "=== Status ==="
if docker ps | grep -q SIMIR_Z; then
    echo "🟢 Container SIMIR_Z está RODANDO"
    echo "   Use './dev.sh logs-f' para acompanhar logs"
elif docker ps -a | grep -q SIMIR_Z; then
    echo "🟡 Container SIMIR_Z existe mas está PARADO"
    echo "   Use './dev.sh start' para iniciar"
else
    echo "⚪ Container SIMIR_Z não existe"
    echo "   Use './run-test.sh' para criar e testar"
fi

echo
echo "=== Próximos passos ==="
echo "1. Execute './run-test.sh' para testar o container"
echo "2. Use './dev.sh logs-f' para acompanhar os logs"
echo "3. Consulte 'scripts/README.md' para troubleshooting"

echo
echo "Validação concluída!"
