#!/bin/bash

# Script para configurar e iniciar o monitoramento de port-scan no SIMIR

echo "=== Configurador de Monitoramento Port-Scan SIMIR ==="
echo

# Função para configurar email
configure_email() {
    echo "Configuração de Email para Alertas"
    echo "==================================="
    echo
    echo "Para enviar alertas por email, você precisa configurar:"
    echo "1. Uma conta Gmail (recomendado)"
    echo "2. App Password (não a senha normal da conta)"
    echo
    echo "Como obter App Password do Gmail:"
    echo "1. Acesse https://myaccount.google.com/"
    echo "2. Segurança > Verificação em duas etapas (deve estar ativada)"
    echo "3. Senhas de app > Selecionar app: Mail"
    echo "4. Copie a senha de 16 caracteres gerada"
    echo
    
    read -p "Digite o email remetente (padrão: simir.alerts@gmail.com): " sender_email
    sender_email=${sender_email:-simir.alerts@gmail.com}
    
    read -s -p "Digite a App Password do Gmail: " email_password
    echo
    
    if [ -z "$email_password" ]; then
        echo "⚠ Email não configurado. Alertas serão apenas logados."
        email_password=""
    else
        echo "✓ Email configurado com sucesso!"
    fi
    
    # Salva configuração
    cat > /tmp/simir_email_config.env <<EOF
SIMIR_SENDER_EMAIL=$sender_email
SIMIR_EMAIL_PASSWORD=$email_password
SIMIR_RECIPIENT_EMAIL=rafaelbartorres@gmail.com
EOF
    
    echo "Configuração salva em /tmp/simir_email_config.env"
}

# Função para testar email
test_email() {
    if [ ! -f "/tmp/simir_email_config.env" ]; then
        echo "❌ Configuração de email não encontrada. Execute 'configure' primeiro."
        return 1
    fi
    
    source /tmp/simir_email_config.env
    
    echo "Testando envio de email..."
    docker exec SIMIR_Z python3 /usr/local/bin/port-scan-monitor.py \
        --email-password "$SIMIR_EMAIL_PASSWORD" \
        --test
}

# Função para iniciar monitoramento
start_monitoring() {
    echo "Iniciando monitoramento de port-scan..."
    
    # Verifica se container está rodando
    if ! docker ps | grep -q SIMIR_Z; then
        echo "❌ Container SIMIR_Z não está rodando. Inicie-o primeiro com:"
        echo "   ./dev.sh start"
        return 1
    fi
    
    # Carrega configuração de email se existir
    email_args=""
    if [ -f "/tmp/simir_email_config.env" ]; then
        source /tmp/simir_email_config.env
        if [ -n "$SIMIR_EMAIL_PASSWORD" ]; then
            email_args="--email-password $SIMIR_EMAIL_PASSWORD"
            echo "✓ Configuração de email carregada"
        fi
    fi
    
    echo "Iniciando monitor no container..."
    docker exec -d SIMIR_Z python3 /usr/local/bin/port-scan-monitor.py $email_args --daemon
    
    if [ $? -eq 0 ]; then
        echo "✓ Monitor de port-scan iniciado com sucesso!"
        echo "Para ver logs: docker exec SIMIR_Z tail -f /tmp/simir_monitor.log"
    else
        echo "❌ Erro ao iniciar monitor"
    fi
}

# Função para parar monitoramento
stop_monitoring() {
    echo "Parando monitoramento de port-scan..."
    docker exec SIMIR_Z pkill -f port-scan-monitor.py
    echo "✓ Monitor parado"
}

# Função para ver logs
show_logs() {
    echo "Logs do monitor de port-scan:"
    echo "============================="
    docker exec SIMIR_Z tail -f /tmp/simir_monitor.log
}

# Função para status
show_status() {
    echo "Status do Monitoramento Port-Scan"
    echo "================================="
    
    if ! docker ps | grep -q SIMIR_Z; then
        echo "❌ Container SIMIR_Z não está rodando"
        return 1
    fi
    
    # Verifica se monitor está rodando
    if docker exec SIMIR_Z pgrep -f port-scan-monitor.py >/dev/null 2>&1; then
        echo "✓ Monitor está RODANDO"
        echo "PID: $(docker exec SIMIR_Z pgrep -f port-scan-monitor.py)"
    else
        echo "❌ Monitor NÃO está rodando"
    fi
    
    # Verifica configuração de email
    if [ -f "/tmp/simir_email_config.env" ]; then
        source /tmp/simir_email_config.env
        echo "✓ Email configurado: $SIMIR_SENDER_EMAIL -> $SIMIR_RECIPIENT_EMAIL"
    else
        echo "⚠ Email não configurado"
    fi
    
    # Verifica logs do Zeek
    echo
    echo "Logs do Zeek:"
    if docker exec SIMIR_Z ls /usr/local/zeek/spool/zeek/notice.log >/dev/null 2>&1; then
        echo "✓ notice.log encontrado"
        lines=$(docker exec SIMIR_Z wc -l < /usr/local/zeek/spool/zeek/notice.log)
        echo "  Linhas: $lines"
    else
        echo "⚠ notice.log não encontrado (normal se não houver alertas)"
    fi
    
    # Estado do monitor
    if docker exec SIMIR_Z ls /tmp/simir_monitor_state.json >/dev/null 2>&1; then
        echo "✓ Estado do monitor salvo"
    fi
}

# Função para simular port scan (para teste)
simulate_port_scan() {
    echo "Simulando port scan para teste..."
    echo "⚠ ATENÇÃO: Isso gerará tráfego de rede suspeito!"
    read -p "Continuar? (y/N): " confirm
    
    if [[ $confirm =~ ^[Yy]$ ]]; then
        # Tenta fazer port scan na própria interface
        target_ip="192.168.50.1"  # IP do gateway
        echo "Fazendo port scan em $target_ip..."
        
        for port in 22 23 25 53 80 110 143 443 993 995; do
            timeout 1 bash -c "</dev/tcp/$target_ip/$port" 2>/dev/null
            sleep 0.1
        done
        
        echo "✓ Port scan simulado. Verifique os logs em alguns segundos."
    else
        echo "Simulação cancelada."
    fi
}

# Menu principal
show_help() {
    echo "Uso: $0 [COMANDO]"
    echo
    echo "Comandos disponíveis:"
    echo "  configure    - Configura email para alertas"
    echo "  test-email   - Testa envio de email"
    echo "  start        - Inicia monitoramento"
    echo "  stop         - Para monitoramento"
    echo "  status       - Mostra status do sistema"
    echo "  logs         - Mostra logs em tempo real"
    echo "  simulate     - Simula port scan para teste"
    echo "  help         - Mostra esta ajuda"
    echo
}

case "$1" in
    "configure")
        configure_email
        ;;
    "test-email")
        test_email
        ;;
    "start")
        start_monitoring
        ;;
    "stop")
        stop_monitoring
        ;;
    "status")
        show_status
        ;;
    "logs")
        show_logs
        ;;
    "simulate")
        simulate_port_scan
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
