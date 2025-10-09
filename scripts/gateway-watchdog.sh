#!/bin/bash

##############################################################################
# Gateway Watchdog - SIMIR
# Monitora e reativa o gateway se houver problemas
##############################################################################

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

LAN_IF="enx00e04c672dbf"
LAN_IP="10.99.99.1"
WAN_IF="enp0s31f6"

check_and_fix() {
    local fixed=0
    
    # Verifica se interface existe
    if ! ip link show "$LAN_IF" &>/dev/null; then
        echo -e "${RED}✗${NC} Interface $LAN_IF não existe"
        return 1
    fi
    
    # Verifica se tem IP
    if ! ip addr show "$LAN_IF" | grep -q "$LAN_IP"; then
        echo -e "${YELLOW}⚠${NC} IP $LAN_IP não configurado, corrigindo..."
        sudo ip addr add ${LAN_IP}/24 dev "$LAN_IF" 2>/dev/null
        sudo ip link set "$LAN_IF" up
        fixed=1
    fi
    
    # Verifica IP forwarding
    if [[ $(cat /proc/sys/net/ipv4/ip_forward) != "1" ]]; then
        echo -e "${YELLOW}⚠${NC} IP forwarding desabilitado, corrigindo..."
        sudo sysctl -w net.ipv4.ip_forward=1 >/dev/null
        fixed=1
    fi
    
    # Verifica regras NAT
    if ! sudo iptables -t nat -L POSTROUTING -n | grep -q "MASQUERADE.*$WAN_IF"; then
        echo -e "${YELLOW}⚠${NC} Regra NAT ausente, corrigindo..."
        sudo iptables -t nat -A POSTROUTING -o "$WAN_IF" -j MASQUERADE
        fixed=1
    fi
    
    # Verifica regras FORWARD
    if ! sudo iptables -L FORWARD -n | grep -q "$LAN_IF.*$WAN_IF"; then
        echo -e "${YELLOW}⚠${NC} Regras FORWARD ausentes, corrigindo..."
        sudo iptables -A FORWARD -i "$LAN_IF" -o "$WAN_IF" -j ACCEPT
        sudo iptables -A FORWARD -i "$WAN_IF" -o "$LAN_IF" -m state --state RELATED,ESTABLISHED -j ACCEPT
        fixed=1
    fi
    
    # Verifica dnsmasq
    if ! pgrep -f "dnsmasq -C /etc/dnsmasq.conf" >/dev/null; then
        echo -e "${YELLOW}⚠${NC} dnsmasq não está rodando, corrigindo..."
        sudo killall -9 dnsmasq 2>/dev/null
        sleep 1
        sudo dnsmasq -C /etc/dnsmasq.conf --log-queries --log-dhcp
        fixed=1
    fi
    
    if [[ $fixed -eq 1 ]]; then
        echo -e "${GREEN}✓${NC} Gateway restaurado"
    else
        echo -e "${GREEN}✓${NC} Gateway OK"
    fi
    
    return 0
}

if [[ "$1" == "--daemon" ]]; then
    echo "Iniciando watchdog em modo daemon..."
    while true; do
        check_and_fix
        sleep 30
    done
else
    check_and_fix
fi
