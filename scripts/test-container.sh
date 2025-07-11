#!/bin/bash

echo "=== Teste do Container Zeek SIMIR ==="

# Função para usar docker-compose correto
docker_compose() {
    if command -v docker-compose >/dev/null 2>&1; then
        docker-compose "$@"
    else
        docker compose "$@"
    fi
}

# Verifica se o Docker está rodando
if ! docker ps >/dev/null 2>&1; then
    echo "ERRO: Docker não está rodando ou não temos permissão"
    exit 1
fi

# Para o container atual se estiver rodando
echo "Parando container atual..."
docker stop SIMIR_Z 2>/dev/null || true
docker rm SIMIR_Z 2>/dev/null || true

# Rebuild da imagem
echo "Fazendo rebuild da imagem..."
cd /home/testserver/zeek-container/SIMIR
docker_compose build

# Testa a interface antes de iniciar
echo "Testando interface de rede no host..."
IFACE="enx000ec89f6cc0"
if ! ip link show "$IFACE" >/dev/null 2>&1; then
    echo "ERRO: Interface $IFACE não encontrada no host!"
    echo "Interfaces disponíveis:"
    ip link show | grep -E "^[0-9]+:" | cut -d: -f2 | sed 's/^ *//'
    exit 1
fi

# Inicia o container
echo "Iniciando container..."
docker_compose up -d

# Aguarda um pouco e verifica logs
sleep 5
echo "Primeiros logs do container:"
docker logs SIMIR_Z --tail 20

echo
echo "Para acompanhar logs em tempo real, execute:"
echo "docker logs -f SIMIR_Z"
