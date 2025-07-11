#!/bin/bash

# Configuração Rápida de Email - SIMIR
echo "📧 Configuração Rápida de Email"
echo "==============================="
echo

echo "⚠️  IMPORTANTE: Para funcionar, você precisa:"
echo "1. Ativar verificação em duas etapas no Gmail"
echo "2. Gerar uma App Password específica"
echo

echo "🔗 Siga estes passos:"
echo "1. Acesse: https://myaccount.google.com/security"
echo "2. Ative 'Verificação em duas etapas'"
echo "3. Vá em 'Senhas de app'"
echo "4. Selecione 'Mail' e digite 'SIMIR'"
echo "5. Copie a senha de 16 caracteres"
echo

read -p "✅ Já tem uma App Password? (s/N): " tem_app_password

if [[ ! $tem_app_password =~ ^[Ss]$ ]]; then
    echo
    echo "📱 Vou abrir o link para você configurar..."
    echo "   https://myaccount.google.com/security"
    echo
    echo "⏳ Configure a App Password e execute este script novamente"
    exit 0
fi

echo
read -p "📧 Seu email Gmail: " email_gmail
read -s -p "🔐 App Password (16 caracteres): " app_password
echo

# Remove espaços
app_password=$(echo "$app_password" | tr -d ' ')

# Valida entrada
if [ -z "$email_gmail" ] || [ -z "$app_password" ]; then
    echo "❌ Email e App Password são obrigatórios!"
    exit 1
fi

# Cria configuração
export SIMIR_SENDER_EMAIL="$email_gmail"
export SIMIR_EMAIL_PASSWORD="$app_password"
export SIMIR_RECIPIENT_EMAIL="rafaelbartorres@gmail.com"

echo
echo "🧪 Testando configuração..."

# Teste direto
python3 << EOF
import smtplib
import sys
from email.mime.text import MIMEText

try:
    print("📡 Conectando ao Gmail...")
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    
    print("🔐 Autenticando...")
    server.login('$email_gmail', '$app_password')
    
    print("📨 Enviando email de teste...")
    msg = MIMEText('Email de teste do sistema SIMIR. Se você recebeu esta mensagem, a configuração está funcionando!')
    msg['Subject'] = '[SIMIR] ✅ Configuração de Email Funcionando'
    msg['From'] = '$email_gmail'
    msg['To'] = 'rafaelbartorres@gmail.com'
    
    server.send_message(msg)
    server.quit()
    
    print("✅ SUCESSO! Email de teste enviado para rafaelbartorres@gmail.com")
    
    # Salva configuração se o teste passou
    with open('/tmp/simir_email_config.env', 'w') as f:
        f.write(f'export SIMIR_SENDER_EMAIL="{email_gmail}"\n')
        f.write(f'export SIMIR_EMAIL_PASSWORD="{app_password}"\n')
        f.write('export SIMIR_RECIPIENT_EMAIL="rafaelbartorres@gmail.com"\n')
    
    print("💾 Configuração salva com sucesso!")
    sys.exit(0)
    
except Exception as e:
    print(f"❌ ERRO: {e}")
    print()
    print("🔧 Possíveis problemas:")
    if "Username and Password not accepted" in str(e):
        print("  • App Password incorreta ou não gerada")
        print("  • Verificação em duas etapas não ativa")
    elif "authentication failed" in str(e).lower():
        print("  • Credenciais incorretas")
    else:
        print("  • Problema de conexão ou configuração")
    
    print()
    print("💡 Soluções:")
    print("  1. Gere uma NOVA App Password")
    print("  2. Copie sem espaços ou caracteres extras")
    print("  3. Verifique se 2FA está ativo no Gmail")
    sys.exit(1)
EOF

if [ $? -eq 0 ]; then
    echo
    echo "🎉 Configuração concluída com sucesso!"
    echo
    echo "🚀 Próximos passos:"
    echo "   ./scripts/simir-control.sh start-monitor"
    echo "   ./scripts/simir-control.sh simulate"
else
    echo
    echo "❌ Configuração falhou. Tente novamente com uma nova App Password."
fi
