#!/bin/bash

# SIMIR - Configuração de Email Simplificada
echo "📧 SIMIR - Configuração de Email"
echo "================================"
echo

echo "⚠️  Problemas comuns com Gmail:"
echo "• Erro 'Username and Password not accepted'"
echo "• Necessário App Password (não senha normal)"
echo

echo "🔧 Solução:"
echo "1. Acesse: https://myaccount.google.com/security"
echo "2. Ative 'Verificação em duas etapas'"
echo "3. Vá em 'Senhas de app' → 'Mail' → 'SIMIR'"
echo "4. Copie a senha de 16 caracteres"
echo

read -p "✅ Já configurou App Password? (s/n): " confirmado
if [[ ! $confirmado =~ ^[Ss]$ ]]; then
    echo "⏳ Configure primeiro e execute novamente"
    exit 0
fi

echo
read -p "📧 Seu email Gmail: " email
read -s -p "🔐 App Password (16 chars): " senha
echo
echo

# Remove espaços
senha=$(echo "$senha" | tr -d ' ')

if [ -z "$email" ] || [ -z "$senha" ]; then
    echo "❌ Email e senha são obrigatórios"
    exit 1
fi

echo "🧪 Testando..."

# Cria script Python temporário
cat > /tmp/teste_email_simir.py << 'EOF'
import smtplib
import sys
from email.mime.text import MIMEText

email = sys.argv[1]
senha = sys.argv[2]

try:
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(email, senha)
    
    msg = MIMEText('✅ Teste SIMIR - Email funcionando!')
    msg['Subject'] = '[SIMIR] Configuração OK'
    msg['From'] = email
    msg['To'] = 'rafaelbartorres@gmail.com'
    
    server.send_message(msg)
    server.quit()
    
    print("✅ SUCESSO! Email enviado para rafaelbartorres@gmail.com")
    
    # Salva config
    with open('/tmp/simir_email_config.env', 'w') as f:
        f.write(f'export SIMIR_SENDER_EMAIL="{email}"\n')
        f.write(f'export SIMIR_EMAIL_PASSWORD="{senha}"\n')
        f.write('export SIMIR_RECIPIENT_EMAIL="rafaelbartorres@gmail.com"\n')
    
    print("💾 Configuração salva!")
    
except Exception as e:
    print(f"❌ ERRO: {e}")
    if "Username and Password not accepted" in str(e):
        print("💡 App Password incorreta - gere uma nova")
    elif "BadCredentials" in str(e):
        print("💡 Verifique se 2FA está ativo e App Password correta")
    else:
        print("💡 Problema de autenticação")
    sys.exit(1)
EOF

# Executa teste
python3 /tmp/teste_email_simir.py "$email" "$senha"

if [ $? -eq 0 ]; then
    echo
    echo "🎉 Email configurado com sucesso!"
    echo
    echo "🚀 Próximos passos:"
    echo "   source /tmp/simir_email_config.env"
    echo "   ./scripts/simir-control.sh start-monitor"
    echo "   ./scripts/simir-control.sh simulate"
    echo
    echo "📁 Configuração salva em: /tmp/simir_email_config.env"
else
    echo
    echo "❌ Configuração falhou"
    echo "🔧 Gere uma NOVA App Password e tente novamente"
fi

# Limpa arquivo temporário
rm -f /tmp/teste_email_simir.py
