#!/bin/bash

# Script para testar o sistema de detecção de força bruta do SIMIR
# Este script executa testes simulados para verificar se o detector está funcionando

set -e

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Diretórios
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
SITE_DIR="$PROJECT_ROOT/site"
LOGS_DIR="$PROJECT_ROOT/logs"

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

show_banner() {
    echo -e "${BLUE}"
    cat << "EOF"
╔══════════════════════════════════════════════════════╗
║             SIMIR - Teste Força Bruta                ║
║        Sistema de Detecção de Ataques                ║
╚══════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

check_dependencies() {
    log_info "Verificando dependências..."
    
    # Verifica se o Docker está instalado e em execução
    if ! command -v docker &> /dev/null; then
        log_error "Docker não encontrado. Instale o Docker primeiro."
        exit 1
    fi
    
    # Verifica se o container SIMIR está rodando
    if ! docker ps | grep -q "SIMIR_Z"; then
        log_warning "Container SIMIR não está em execução."
        log_info "Tentando iniciar o container..."
        cd "$PROJECT_ROOT"
        if docker-compose up -d zeek; then
            log_success "Container iniciado com sucesso"
            sleep 5  # Aguarda inicialização
        else
            log_error "Falha ao iniciar o container SIMIR"
            exit 1
        fi
    fi
    
    if [ ! -f "$SITE_DIR/brute-force-detector.zeek" ]; then
        log_error "Detector de força bruta não encontrado em $SITE_DIR"
        exit 1
    fi
    
    if [ ! -f "$SITE_DIR/test-brute-force.zeek" ]; then
        log_error "Script de teste não encontrado em $SITE_DIR"
        exit 1
    fi
    
    log_success "Dependências verificadas"
}

backup_logs() {
    log_info "Fazendo backup dos logs existentes..."
    
    if [ -f "$LOGS_DIR/notice.log" ]; then
        cp "$LOGS_DIR/notice.log" "$LOGS_DIR/notice.log.backup.$(date +%Y%m%d_%H%M%S)"
        log_success "Backup criado"
    fi
}

run_syntax_check() {
    log_info "Verificando sintaxe do detector de força bruta..."
    
    cd "$PROJECT_ROOT"
    if docker exec SIMIR_Z zeek -C /usr/local/zeek/share/zeek/site/brute-force-detector.zeek; then
        log_success "Sintaxe OK"
    else
        log_error "Erro de sintaxe no detector"
        exit 1
    fi
}

run_test() {
    log_info "Executando testes de detecção de força bruta..."
    
    cd "$PROJECT_ROOT"
    
    # Limpa logs antigos de teste no container
    docker exec SIMIR_Z rm -f /usr/local/zeek/spool/zeek/notice.log
    
    # Executa o teste no container
    if docker exec SIMIR_Z zeek -C /usr/local/zeek/share/zeek/site/test-brute-force.zeek; then
        log_success "Teste executado com sucesso"
    else
        log_error "Falha na execução do teste"
        exit 1
    fi
    
    # Aguarda um pouco para os logs serem escritos
    sleep 2
    
    # Verifica se foram gerados alertas
    if [ -f "$LOGS_DIR/notice.log" ]; then
        local alert_count=$(wc -l < "$LOGS_DIR/notice.log")
        if [ "$alert_count" -gt 0 ]; then
            log_success "Gerados $alert_count alertas de força bruta"
            echo ""
            log_info "Alertas detectados:"
            if command -v jq &> /dev/null; then
                tail -10 "$LOGS_DIR/notice.log" | jq -r '.msg' 2>/dev/null || tail -10 "$LOGS_DIR/notice.log"
            else
                tail -10 "$LOGS_DIR/notice.log"
            fi
        else
            log_warning "Nenhum alerta foi gerado"
        fi
    else
        log_warning "Arquivo notice.log não foi criado em $LOGS_DIR"
    fi
}

run_live_test() {
    log_info "Verificando monitoramento em tempo real..."
    
    # Verifica se o container está monitorando
    log_info "Status do container SIMIR:"
    docker ps | grep SIMIR_Z || log_warning "Container não encontrado"
    
    log_info "Verificando logs em tempo real por 10 segundos..."
    log_info "Execute alguns comandos SSH, FTP ou HTTP em outra janela para testar"
    
    # Monitora os logs em tempo real
    timeout 10s tail -f "$LOGS_DIR/notice.log" 2>/dev/null || log_info "Nenhum novo alerta detectado"
    
    # Verifica logs recentes
    if [ -f "$LOGS_DIR/notice.log" ]; then
        local recent_alerts=$(tail -5 "$LOGS_DIR/notice.log" | wc -l)
        if [ "$recent_alerts" -gt 0 ]; then
            log_success "Alertas recentes encontrados:"
            echo ""
            tail -5 "$LOGS_DIR/notice.log" | jq -r '.msg' 2>/dev/null || tail -5 "$LOGS_DIR/notice.log"
        else
            log_info "Nenhum alerta recente encontrado"
        fi
    fi
}

show_configuration() {
    log_info "Configuração atual do detector:"
    echo ""
    grep -E "threshold|time_window" "$SITE_DIR/brute-force-detector.zeek" | grep -v "#"
    echo ""
}

cleanup() {
    log_info "Limpeza não necessária - logs mantidos em $LOGS_DIR"
    log_success "Use 'docker logs SIMIR_Z' para ver logs do container"
}

show_help() {
    echo "Uso: $0 [opção]"
    echo ""
    echo "Opções:"
    echo "  -t, --test         Executa teste de simulação"
    echo "  -l, --live         Executa teste com interface de rede"
    echo "  -c, --config       Mostra configuração atual"
    echo "  -s, --syntax       Verifica apenas a sintaxe"
    echo "  -h, --help         Mostra esta ajuda"
    echo ""
}

main() {
    show_banner
    
    case "${1:-}" in
        -t|--test)
            check_dependencies
            run_syntax_check
            run_test
            ;;
        -l|--live)
            check_dependencies
            run_syntax_check
            run_live_test
            ;;
        -c|--config)
            show_configuration
            ;;
        -s|--syntax)
            check_dependencies
            run_syntax_check
            ;;
        -h|--help)
            show_help
            ;;
        *)
            log_info "Executando teste completo..."
            check_dependencies
            backup_logs
            run_syntax_check
            show_configuration
            run_test
            cleanup
            echo ""
            log_success "Teste de força bruta concluído!"
            log_info "Para executar teste em tempo real, use: $0 --live"
            ;;
    esac
}

main "$@"
