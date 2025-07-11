#!/bin/bash

# Script de desenvolvimento para debug do container SIMIR

# Função para usar docker-compose correto
docker_compose() {
    if command -v docker-compose >/dev/null 2>&1; then
        docker-compose "$@"
    else
        docker compose "$@"
    fi
}

show_help() {
    echo "Script de desenvolvimento SIMIR Zeek"
    echo
    echo "Uso: $0 [COMANDO]"
    echo
    echo "Comandos disponíveis:"
    echo "  build       - Faz rebuild da imagem Docker"
    echo "  start       - Inicia o container"
    echo "  stop        - Para o container"
    echo "  restart     - Para e inicia o container"
    echo "  logs        - Mostra logs do container"
    echo "  logs-f      - Acompanha logs em tempo real"
    echo "  shell       - Abre shell no container"
    echo "  status      - Mostra status do container"
    echo "  test-iface  - Testa interface de rede"
    echo "  clean       - Remove container e imagens órfãs"
    echo "  help        - Mostra esta ajuda"
    echo
}

case "$1" in
    "build")
        echo "Fazendo rebuild da imagem..."
        docker_compose build
        ;;
    "start")
        echo "Iniciando container..."
        docker_compose up -d
        ;;
    "stop")
        echo "Parando container..."
        docker_compose down
        ;;
    "restart")
        echo "Reiniciando container..."
        docker_compose down
        docker_compose up -d
        ;;
    "logs")
        echo "Mostrando logs do container..."
        docker logs SIMIR_Z
        ;;
    "logs-f")
        echo "Acompanhando logs em tempo real (Ctrl+C para sair)..."
        docker logs -f SIMIR_Z
        ;;
    "shell")
        echo "Abrindo shell no container..."
        docker exec -it SIMIR_Z /bin/bash
        ;;
    "status")
        echo "Status do container:"
        docker ps -a | grep SIMIR_Z
        echo
        echo "Uso de recursos:"
        docker stats SIMIR_Z --no-stream 2>/dev/null || echo "Container não está rodando"
        ;;
    "test-iface")
        echo "Testando interface de rede..."
        ./scripts/check-interface.sh "${2:-enx000ec89f6cc0}"
        ;;
    "clean")
        echo "Limpando containers e imagens..."
        docker_compose down
        docker system prune -f
        ;;
    "help"|"")
        show_help
        ;;
    *)
        echo "Comando desconhecido: $1"
        echo
        show_help
        exit 1
        ;;
esac
