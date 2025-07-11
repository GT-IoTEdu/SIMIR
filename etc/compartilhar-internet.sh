#!/bin/bash

# Interface com acesso à Internet
INTERNET_IF="eno1"

# Interface da rede interna
LAN_IF="enx000ec89f6cc0"

# Regras de NAT e redirecionamento
sudo ethtool -K enx000ec89f6cc0 rx off tx off
# Reativa IP forwarding
sudo sysctl -w net.ipv4.ip_forward=1

# Recria regra de NAT
sudo iptables -t nat -A POSTROUTING -o eno1 -j MASQUERADE

# Libera tráfego entre as interfaces
sudo iptables -A FORWARD -i eno1 -o enx000ec89f6cc0 -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo iptables -A FORWARD -i enx000ec89f6cc0 -o eno1 -j ACCEPT
