#!/bin/bash

# SIMIR - Script de Inicialização Rápida
# Configura rapidamente o sistema de monitoramento de port scan

set -e

# Cores
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}🚀 SIMIR - Sistema de Monitoramento de Port Scan${NC}"
echo -e "${BLUE}=================================================${NC}"
echo

# Verifica se está no diretório correto
if [ ! -f "docker-compose.yml" ] || [ ! -f "Dockerfile" ]; then
    echo -e "${RED}❌ Execute este script no diretório raiz do projeto SIMIR${NC}"
    exit 1
fi

# Função para configuração rápida de email
quick_email_setup() {
    echo -e "${YELLOW}📧 Configuração de Email para Alertas${NC}"
    echo
    echo "Para receber alertas de port scan por email, configure:"
    echo "• Email: rafaelbartorres@gmail.com (já configurado)"
    echo "• App Password do Gmail (necessário)"
    echo
    echo -e "${BLUE}Como obter App Password:${NC}"
    echo "1. https://myaccount.google.com/"
    echo "2. Segurança > Verificação em duas etapas"
    echo "3. Senhas de app > Mail"
    echo "4. Copie a senha de 16 caracteres"
    echo
    
    read -p "Deseja configurar email agora? (s/N): " setup_email
    
    if [[ $setup_email =~ ^[Ss]$ ]]; then
        read -p "Email remetente [simir.alerts@gmail.com]: " sender_email
        sender_email=${sender_email:-simir.alerts@gmail.com}
        
        read -s -p "App Password do Gmail: " email_password
        echo
        
        if [ -n "$email_password" ]; then
            # Salva configuração para o container
            export SIMIR_SENDER_EMAIL="$sender_email"
            export SIMIR_EMAIL_PASSWORD="$email_password"
            export SIMIR_RECIPIENT_EMAIL="rafaelbartorres@gmail.com"
            
            echo -e "${GREEN}✓ Email configurado!${NC}"
            
            # Adiciona variáveis ao docker-compose
            if ! grep -q "SIMIR_EMAIL_PASSWORD" docker-compose.yml; then
                echo "Atualizando docker-compose.yml com configurações de email..."
                sed -i '/environment:/a \      - SIMIR_SENDER_EMAIL='$sender_email'' docker-compose.yml
                sed -i '/environment:/a \      - SIMIR_EMAIL_PASSWORD='$email_password'' docker-compose.yml
                sed -i '/environment:/a \      - SIMIR_RECIPIENT_EMAIL=rafaelbartorres@gmail.com' docker-compose.yml
            fi
        else
            echo -e "${YELLOW}⚠ Email não configurado. Alertas serão apenas logados.${NC}"
        fi
    else
        echo -e "${YELLOW}⚠ Pulando configuração de email. Use './scripts/simir-control.sh configure' depois.${NC}"
    fi
    echo
}

# Configuração de email
quick_email_setup

# Construir imagem
echo -e "${BLUE}🔨 Construindo imagem Docker...${NC}"
docker-compose build

# Iniciar sistema
echo -e "${BLUE}🚀 Iniciando sistema SIMIR...${NC}"
docker-compose up -d

# Aguardar container inicializar
echo -e "${BLUE}⏳ Aguardando inicialização...${NC}"
sleep 15

# Verificar status
echo -e "${BLUE}📊 Status do Sistema:${NC}"
echo

# Status do container
if docker-compose ps | grep -q "Up"; then
    echo -e "${GREEN}✓ Container Zeek: Rodando${NC}"
    
    # Verificar logs do Zeek
    echo -e "${BLUE}📋 Últimos logs do Zeek:${NC}"
    docker-compose logs --tail=10
    
    echo
    echo -e "${GREEN}✓ Sistema SIMIR iniciado com sucesso!${NC}"
    echo
    echo -e "${BLUE}📚 Próximos passos:${NC}"
    echo "• Ver logs em tempo real: ${YELLOW}docker-compose logs -f${NC}"
    echo "• Gerenciar sistema: ${YELLOW}./scripts/simir-control.sh${NC}"
    echo "• Testar detecção: ${YELLOW}./scripts/simir-control.sh simulate${NC}"
    echo "• Ver status: ${YELLOW}./scripts/simir-control.sh status${NC}"
    
    # Teste automático de email se configurado
    if [ -n "$SIMIR_EMAIL_PASSWORD" ]; then
        echo
        read -p "Enviar email de teste? (s/N): " test_email
        if [[ $test_email =~ ^[Ss]$ ]]; then
            echo -e "${BLUE}📧 Enviando email de teste...${NC}"
            docker exec SIMIR_Z python3 /usr/local/bin/simir-monitor.py --test-email
        fi
    fi
    
else
    echo -e "${RED}❌ Container falhou ao iniciar${NC}"
    echo -e "${BLUE}📋 Logs de erro:${NC}"
    docker-compose logs
    exit 1
fi

echo
echo -e "${GREEN}🎉 SIMIR está pronto para detectar port scans!${NC}"
echo -e "${BLUE}Alertas serão enviados para: rafaelbartorres@gmail.com${NC}"
