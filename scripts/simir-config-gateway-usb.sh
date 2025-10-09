#!/bin/bash

##############################################################################
# SIMIR Gateway Setup
# Configura uma interface de rede para atuar como gateway, fornecendo
# DHCP e acesso à internet para dispositivos conectados.
##############################################################################

set -e

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Variáveis de configuração
LAN_IF="enx00e04c672dbf"  # Interface onde o notebook será conectado
WAN_IF=""                  # Interface com acesso à internet (detectada automaticamente)
LAN_IP="10.99.99.1"
LAN_SUBNET="10.99.99.0/24"
DHCP_RANGE_START="10.99.99.10"
DHCP_RANGE_END="10.99.99.100"
DHCP_LEASE_TIME="12h"
DNS_SERVERS="8.8.8.8,8.8.4.4"

# Funções auxiliares
print_header() {
    echo -e "\n${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}\n"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "Este script precisa ser executado como root"
        echo "Use: sudo $0"
        exit 1
    fi
}

detect_wan_interface() {
    print_info "Detectando interface com acesso à internet..."
    
    # Tenta identificar a interface padrão de rota
    WAN_IF=$(ip route | grep default | awk '{print $5}' | head -n1)
    
    if [[ -z "$WAN_IF" ]]; then
        print_warning "Não foi possível detectar automaticamente a interface WAN"
        echo ""
        echo "Interfaces disponíveis:"
        ip -br link show | grep -v "lo" | awk '{print "  - " $1 " (" $2 ")"}'
        echo ""
        read -p "Digite o nome da interface WAN (ex: eth0, wlp3s0): " WAN_IF
        
        if [[ -z "$WAN_IF" ]]; then
            print_error "Interface WAN não especificada"
            exit 1
        fi
    fi
    
    # Verifica se a interface existe
    if ! ip link show "$WAN_IF" &>/dev/null; then
        print_error "Interface $WAN_IF não existe"
        exit 1
    fi
    
    print_success "Interface WAN detectada: $WAN_IF"
}

check_lan_interface() {
    print_info "Verificando interface LAN: $LAN_IF"
    
    if ! ip link show "$LAN_IF" &>/dev/null; then
        print_error "Interface $LAN_IF não existe"
        echo ""
        echo "Interfaces disponíveis:"
        ip -br link show | grep -v "lo" | awk '{print "  - " $1}'
        exit 1
    fi
    
    print_success "Interface LAN encontrada: $LAN_IF"
}

install_dependencies() {
    print_info "Verificando dependências..."
    
    # Verifica se o serviço dnsmasq existe no systemd
    if ! systemctl list-unit-files | grep -q "^dnsmasq.service"; then
        print_warning "Serviço dnsmasq não está instalado. Instalando pacote completo..."
        
        if command -v apt &>/dev/null; then
            # Remove dnsmasq-base se existir
            apt remove -y dnsmasq-base 2>/dev/null || true
            apt update -qq
            # Usa --force-confold para manter configurações existentes automaticamente
            DEBIAN_FRONTEND=noninteractive apt install -y -o Dpkg::Options::="--force-confold" dnsmasq iptables
        elif command -v yum &>/dev/null; then
            yum install -y dnsmasq iptables
        elif command -v pacman &>/dev/null; then
            pacman -S --noconfirm dnsmasq iptables
        else
            print_error "Gerenciador de pacotes não suportado"
            exit 1
        fi
        
        print_success "dnsmasq instalado com sucesso"
    else
        print_success "dnsmasq já está instalado"
    fi
}

configure_lan_interface() {
    print_info "Configurando interface LAN..."
    
    # Remove IPs anteriores
    ip addr flush dev "$LAN_IF" 2>/dev/null || true
    
    # Configura novo IP
    ip addr add "${LAN_IP}/24" dev "$LAN_IF"
    ip link set "$LAN_IF" up
    
    print_success "Interface $LAN_IF configurada com IP $LAN_IP"
}

enable_ip_forwarding() {
    print_info "Habilitando IP forwarding..."
    
    # Temporário
    sysctl -w net.ipv4.ip_forward=1 >/dev/null
    
    # Permanente
    if ! grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf 2>/dev/null; then
        echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
        print_success "IP forwarding habilitado permanentemente"
    else
        print_success "IP forwarding já estava habilitado"
    fi
}

configure_nat() {
    print_info "Configurando NAT (masquerade)..."
    
    # Limpa regras antigas do SIMIR
    iptables -t nat -D POSTROUTING -o "$WAN_IF" -j MASQUERADE 2>/dev/null || true
    iptables -D FORWARD -i "$LAN_IF" -o "$WAN_IF" -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -i "$WAN_IF" -o "$LAN_IF" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
    
    # Adiciona novas regras
    iptables -t nat -A POSTROUTING -o "$WAN_IF" -j MASQUERADE
    iptables -A FORWARD -i "$LAN_IF" -o "$WAN_IF" -j ACCEPT
    iptables -A FORWARD -i "$WAN_IF" -o "$LAN_IF" -m state --state RELATED,ESTABLISHED -j ACCEPT
    
    print_success "NAT configurado para $LAN_IF → $WAN_IF"
}

configure_dnsmasq() {
    print_info "Configurando servidor DHCP/DNS (dnsmasq)..."
    
    # Backup da configuração original
    if [[ -f /etc/dnsmasq.conf ]] && [[ ! -f /etc/dnsmasq.conf.bak ]]; then
        cp /etc/dnsmasq.conf /etc/dnsmasq.conf.bak
        print_info "Backup criado: /etc/dnsmasq.conf.bak"
    fi
    
    # Cria nova configuração
    cat > /etc/dnsmasq.conf << EOF
# SIMIR Gateway Configuration
# Gerado automaticamente por setup-gateway.sh

# Interface onde o DHCP vai escutar
interface=$LAN_IF

# Não escute na interface WAN
except-interface=$WAN_IF

# Não leia /etc/resolv.conf para servidores DNS
no-resolv

# Range de IPs para distribuir
dhcp-range=$DHCP_RANGE_START,$DHCP_RANGE_END,$DHCP_LEASE_TIME

# Gateway (este servidor)
dhcp-option=3,$LAN_IP

# Servidores DNS
dhcp-option=6,$DNS_SERVERS

# Domínio local
domain=simir.lab

# Arquivo de leases
dhcp-leasefile=/var/lib/misc/dnsmasq.leases

# Servidor DNS upstream
server=8.8.8.8
server=8.8.4.4

# Log de queries (útil para debug)
log-queries
log-dhcp

# Arquivo de log
log-facility=/var/log/dnsmasq.log

# Não use /etc/hosts para resolução
no-hosts

# Cache DNS
cache-size=1000
EOF
    
    print_success "Configuração do dnsmasq criada"
}

disable_systemd_resolved_dns() {
    print_info "Desabilitando DNS do systemd-resolved (conflito com porta 53)..."
    
    # Cria diretório de configuração se não existir
    mkdir -p /etc/systemd/resolved.conf.d
    
    # Configura systemd-resolved para não escutar na porta 53
    cat > /etc/systemd/resolved.conf.d/disable-stub.conf << EOF
[Resolve]
DNSStubListener=no
DNS=8.8.8.8 8.8.4.4
EOF
    
    # Reinicia systemd-resolved
    systemctl restart systemd-resolved
    
    # Aguarda um momento
    sleep 1
    
    print_success "systemd-resolved configurado"
}

start_dnsmasq() {
    print_info "Iniciando serviço dnsmasq..."
    
    # Para o serviço se estiver rodando
    systemctl stop dnsmasq 2>/dev/null || true
    
    # Testa a configuração
    if ! dnsmasq --test 2>/dev/null; then
        print_error "Erro na configuração do dnsmasq"
        dnsmasq --test
        exit 1
    fi
    
    # Desabilita DNS stub do systemd-resolved se estiver em conflito
    if lsof -i :53 2>/dev/null | grep -q systemd-resolve; then
        disable_systemd_resolved_dns
    fi
    
    # Recarrega systemd para reconhecer o serviço
    print_info "Recarregando systemd..."
    systemctl daemon-reload
    
    # Habilita o serviço
    systemctl enable dnsmasq 2>/dev/null
    
    # Inicia o serviço
    systemctl start dnsmasq
    
    # Aguarda um momento para o serviço iniciar
    sleep 2
    
    if systemctl is-active --quiet dnsmasq; then
        print_success "dnsmasq iniciado com sucesso"
    else
        print_error "Falha ao iniciar dnsmasq"
        print_info "Verificando logs..."
        journalctl -xeu dnsmasq.service --no-pager -n 30
        exit 1
    fi
}

create_systemd_service() {
    print_info "Criando serviço systemd para persistência..."
    
    # Cria script de inicialização
    cat > /usr/local/bin/simir-gateway-start.sh << EOF
#!/bin/bash
# SIMIR Gateway - Script de inicialização automática

WAN_IF="$WAN_IF"
LAN_IF="$LAN_IF"
LAN_IP="$LAN_IP"

# Configura IP da LAN
ip addr add \${LAN_IP}/24 dev \$LAN_IF 2>/dev/null || true
ip link set \$LAN_IF up

# Habilita forwarding
sysctl -w net.ipv4.ip_forward=1 >/dev/null

# Limpa regras antigas
iptables -t nat -D POSTROUTING -o \$WAN_IF -j MASQUERADE 2>/dev/null || true
iptables -D FORWARD -i \$LAN_IF -o \$WAN_IF -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -i \$WAN_IF -o \$LAN_IF -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true

# Configura NAT
iptables -t nat -A POSTROUTING -o \$WAN_IF -j MASQUERADE
iptables -A FORWARD -i \$LAN_IF -o \$WAN_IF -j ACCEPT
iptables -A FORWARD -i \$WAN_IF -o \$LAN_IF -m state --state RELATED,ESTABLISHED -j ACCEPT

echo "SIMIR Gateway configurado: \$LAN_IF (\$LAN_IP) → \$WAN_IF"
EOF
    
    chmod +x /usr/local/bin/simir-gateway-start.sh
    
    # Cria serviço systemd
    cat > /etc/systemd/system/simir-gateway.service << EOF
[Unit]
Description=SIMIR Gateway Setup
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/simir-gateway-start.sh
RemainAfterExit=yes
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    
    # Recarrega systemd e habilita o serviço
    systemctl daemon-reload
    systemctl enable simir-gateway.service 2>/dev/null
    
    print_success "Serviço systemd criado e habilitado"
}

update_zeek_config() {
    print_info "Atualizando configuração do Zeek..."
    
    COMPOSE_FILE="/home/rafael/SIMIR/docker-compose.yml"
    
    if [[ -f "$COMPOSE_FILE" ]]; then
        # Verifica se já está configurado
        if grep -q "ZEEK_INTERFACE.*$LAN_IF" "$COMPOSE_FILE"; then
            print_success "Zeek já está configurado para monitorar $LAN_IF"
        else
            print_warning "Configure manualmente o Zeek para monitorar $LAN_IF"
            echo "Edite $COMPOSE_FILE e defina:"
            echo "  ZEEK_INTERFACE=$LAN_IF"
        fi
    fi
}

show_summary() {
    print_header "CONFIGURAÇÃO CONCLUÍDA"
    
    echo -e "${GREEN}Gateway SIMIR configurado com sucesso!${NC}\n"
    
    echo "Configuração aplicada:"
    echo "  Interface WAN:  $WAN_IF"
    echo "  Interface LAN:  $LAN_IF"
    echo "  IP do Gateway:  $LAN_IP"
    echo "  Subnet:         $LAN_SUBNET"
    echo "  DHCP Range:     $DHCP_RANGE_START - $DHCP_RANGE_END"
    echo "  DNS Servers:    $DNS_SERVERS"
    echo ""
    
    echo "Próximos passos:"
    echo "  1. Conecte o notebook no cabo da interface $LAN_IF"
    echo "  2. O notebook receberá automaticamente um IP entre $DHCP_RANGE_START e $DHCP_RANGE_END"
    echo "  3. Configure o Zeek para monitorar: ZEEK_INTERFACE=$LAN_IF"
    echo "  4. Reinicie o SIMIR: docker-compose restart zeek"
    echo ""
    
    echo "Comandos úteis:"
    echo "  Ver leases DHCP:     cat /var/lib/misc/dnsmasq.leases"
    echo "  Log do dnsmasq:      tail -f /var/log/dnsmasq.log"
    echo "  Status do gateway:   systemctl status simir-gateway"
    echo "  Monitorar tráfego:   sudo tcpdump -i $LAN_IF"
    echo "  Desabilitar gateway: sudo systemctl stop simir-gateway dnsmasq"
    echo ""
}

show_test_commands() {
    print_header "COMANDOS DE TESTE"
    
    echo "No servidor SIMIR:"
    echo "  # Monitore os alertas"
    echo "  tail -f logs/notice.log"
    echo ""
    echo "  # Veja conexões ativas"
    echo "  watch -n1 'grep \"$LAN_SUBNET\" logs/conn.log | tail -10'"
    echo ""
    
    echo "No notebook (após conectar o cabo):"
    echo "  # Verifique o IP recebido"
    echo "  ip addr show"
    echo ""
    echo "  # Teste conectividade com o gateway"
    echo "  ping -c 3 $LAN_IP"
    echo ""
    echo "  # Teste internet"
    echo "  ping -c 3 8.8.8.8"
    echo "  curl -I https://google.com"
    echo ""
    echo "  # Port scan (vai ser detectado!)"
    echo "  nmap -p 1-1000 $LAN_IP -T4"
    echo ""
}

# Menu principal
show_menu() {
    clear
    print_header "SIMIR - CONFIGURAÇÃO DE GATEWAY"
    
    echo "Este script irá configurar a interface $LAN_IF como gateway,"
    echo "fornecendo DHCP e acesso à internet para dispositivos conectados."
    echo ""
    echo "Opções:"
    echo "  1) Configurar gateway (recomendado)"
    echo "  2) Verificar status"
    echo "  3) Parar gateway"
    echo "  4) Mostrar logs"
    echo "  5) Sair"
    echo ""
    read -p "Escolha uma opção [1-5]: " choice
    
    case $choice in
        1) setup_gateway ;;
        2) check_status ;;
        3) stop_gateway ;;
        4) show_logs ;;
        5) exit 0 ;;
        *) print_error "Opção inválida"; sleep 2; show_menu ;;
    esac
}

setup_gateway() {
    print_header "INICIANDO CONFIGURAÇÃO DO GATEWAY"
    
    check_root
    check_lan_interface
    detect_wan_interface
    install_dependencies
    configure_lan_interface
    enable_ip_forwarding
    configure_nat
    configure_dnsmasq
    start_dnsmasq
    create_systemd_service
    update_zeek_config
    show_summary
    show_test_commands
    
    echo ""
    read -p "Pressione ENTER para voltar ao menu..."
    show_menu
}

check_status() {
    print_header "STATUS DO GATEWAY"
    
    echo "Interface LAN ($LAN_IF):"
    ip addr show "$LAN_IF" 2>/dev/null || echo "  Interface não encontrada"
    echo ""
    
    echo "IP Forwarding:"
    if [[ $(cat /proc/sys/net/ipv4/ip_forward) == "1" ]]; then
        print_success "Habilitado"
    else
        print_error "Desabilitado"
    fi
    echo ""
    
    echo "Serviço dnsmasq:"
    if systemctl is-active --quiet dnsmasq; then
        print_success "Ativo"
    else
        print_error "Inativo"
    fi
    echo ""
    
    echo "Serviço simir-gateway:"
    if systemctl is-active --quiet simir-gateway 2>/dev/null; then
        print_success "Ativo"
    else
        print_warning "Não configurado ou inativo"
    fi
    echo ""
    
    echo "Regras NAT:"
    iptables -t nat -L POSTROUTING -n -v | grep -q MASQUERADE && print_success "Configurado" || print_error "Não configurado"
    echo ""
    
    echo "Leases DHCP ativos:"
    if [[ -f /var/lib/misc/dnsmasq.leases ]]; then
        cat /var/lib/misc/dnsmasq.leases
    else
        echo "  Nenhum lease ativo"
    fi
    echo ""
    
    read -p "Pressione ENTER para voltar ao menu..."
    show_menu
}

stop_gateway() {
    print_header "PARANDO GATEWAY"
    
    check_root
    
    print_info "Parando serviços..."
    systemctl stop dnsmasq 2>/dev/null || true
    systemctl stop simir-gateway 2>/dev/null || true
    
    print_info "Removendo configuração da interface..."
    ip addr del "${LAN_IP}/24" dev "$LAN_IF" 2>/dev/null || true
    
    print_info "Desabilitando IP forwarding..."
    sysctl -w net.ipv4.ip_forward=0 >/dev/null
    
    print_info "Limpando regras iptables..."
    iptables -t nat -D POSTROUTING -o "$WAN_IF" -j MASQUERADE 2>/dev/null || true
    iptables -D FORWARD -i "$LAN_IF" -o "$WAN_IF" -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -i "$WAN_IF" -o "$LAN_IF" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
    
    print_success "Gateway parado com sucesso"
    echo ""
    
    read -p "Deseja desabilitar a inicialização automática? [s/N]: " disable
    if [[ "$disable" =~ ^[Ss]$ ]]; then
        systemctl disable simir-gateway 2>/dev/null || true
        systemctl disable dnsmasq 2>/dev/null || true
        print_success "Inicialização automática desabilitada"
    fi
    
    echo ""
    read -p "Pressione ENTER para voltar ao menu..."
    show_menu
}

show_logs() {
    print_header "LOGS DO GATEWAY"
    
    echo "Escolha o log para visualizar:"
    echo "  1) dnsmasq (DHCP/DNS)"
    echo "  2) systemd (simir-gateway)"
    echo "  3) iptables (regras NAT)"
    echo "  4) Voltar"
    echo ""
    read -p "Opção [1-4]: " log_choice
    
    case $log_choice in
        1)
            if [[ -f /var/log/dnsmasq.log ]]; then
                tail -50 /var/log/dnsmasq.log
            else
                journalctl -u dnsmasq -n 50 --no-pager
            fi
            ;;
        2)
            journalctl -u simir-gateway -n 50 --no-pager
            ;;
        3)
            echo "Regras NAT:"
            iptables -t nat -L -n -v
            echo ""
            echo "Regras FORWARD:"
            iptables -L FORWARD -n -v
            ;;
        4)
            show_menu
            return
            ;;
    esac
    
    echo ""
    read -p "Pressione ENTER para voltar ao menu..."
    show_menu
}

# Execução principal
if [[ $# -eq 0 ]]; then
    show_menu
else
    case "$1" in
        start|setup)
            check_root
            check_lan_interface
            detect_wan_interface
            install_dependencies
            configure_lan_interface
            enable_ip_forwarding
            configure_nat
            configure_dnsmasq
            start_dnsmasq
            create_systemd_service
            update_zeek_config
            show_summary
            ;;
        stop)
            check_root
            systemctl stop dnsmasq simir-gateway 2>/dev/null || true
            ip addr del "${LAN_IP}/24" dev "$LAN_IF" 2>/dev/null || true
            print_success "Gateway parado"
            ;;
        status)
            check_status
            ;;
        *)
            echo "Uso: $0 [start|stop|status]"
            echo "  ou execute sem parâmetros para modo interativo"
            exit 1
            ;;
    esac
fi