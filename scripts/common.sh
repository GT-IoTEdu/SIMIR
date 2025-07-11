#!/bin/bash

# Arquivo de configuração e funções auxiliares para o projeto SIMIR

# Função para usar docker-compose correto (standalone ou integrado)
docker_compose() {
    if command -v docker-compose >/dev/null 2>&1; then
        docker-compose "$@"
    else
        docker compose "$@"
    fi
}

# Função para verificar se o Docker está rodando
check_docker() {
    if ! docker ps >/dev/null 2>&1; then
        echo "ERRO: Docker não está rodando ou não temos permissão"
        return 1
    fi
    return 0
}

# Função para verificar se o container existe
check_container() {
    local container_name="${1:-SIMIR_Z}"
    docker ps -a --format "{{.Names}}" | grep -q "^${container_name}$"
}

# Função para verificar se o container está rodando
is_container_running() {
    local container_name="${1:-SIMIR_Z}"
    docker ps --format "{{.Names}}" | grep -q "^${container_name}$"
}

# Função para obter logs do container
get_container_logs() {
    local container_name="${1:-SIMIR_Z}"
    local tail_lines="${2:-20}"
    
    if check_container "$container_name"; then
        docker logs "$container_name" --tail "$tail_lines"
    else
        echo "Container $container_name não existe"
        return 1
    fi
}

# Função para status detalhado do container
container_status() {
    local container_name="${1:-SIMIR_Z}"
    
    echo "=== Status do Container $container_name ==="
    
    if check_container "$container_name"; then
        if is_container_running "$container_name"; then
            echo "🟢 Container está RODANDO"
            echo
            echo "Informações do container:"
            docker ps --filter "name=$container_name" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
            echo
            echo "Uso de recursos:"
            docker stats "$container_name" --no-stream 2>/dev/null || echo "Não foi possível obter estatísticas"
        else
            echo "🟡 Container existe mas está PARADO"
            docker ps -a --filter "name=$container_name" --format "table {{.Names}}\t{{.Status}}"
        fi
    else
        echo "⚪ Container não existe"
    fi
}

# Exporta as funções para uso em outros scripts
export -f docker_compose
export -f check_docker
export -f check_container
export -f is_container_running
export -f get_container_logs
export -f container_status
