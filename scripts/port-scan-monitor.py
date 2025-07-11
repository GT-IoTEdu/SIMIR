#!/usr/bin/env python3
"""
Sistema de Monitoramento de Port Scan - SIMIR
Monitora logs do Zeek e envia alertas por email quando detecta port scan
"""

import json
import time
import smtplib
import os
import sys
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path
import logging
import argparse

# Configurações
EMAIL_CONFIG = {
    'smtp_server': 'smtp.gmail.com',
    'smtp_port': 587,
    'sender_email': 'simir.alerts@gmail.com',  # Configure com sua conta
    'sender_password': '',  # Configure com app password
    'recipient_email': 'rafaelbartorres@gmail.com'
}

ZEEK_LOG_DIR = '/usr/local/zeek/spool/zeek'
NOTICE_LOG_FILE = os.path.join(ZEEK_LOG_DIR, 'notice.log')
STATE_FILE = '/tmp/simir_monitor_state.json'

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/tmp/simir_monitor.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class PortScanMonitor:
    def __init__(self, config):
        self.config = config
        self.last_position = 0
        self.sent_alerts = set()
        self.load_state()
        
    def load_state(self):
        """Carrega estado anterior do monitoramento"""
        try:
            if os.path.exists(STATE_FILE):
                with open(STATE_FILE, 'r') as f:
                    state = json.load(f)
                    self.last_position = state.get('last_position', 0)
                    self.sent_alerts = set(state.get('sent_alerts', []))
                    logger.info(f"Estado carregado: posição {self.last_position}, {len(self.sent_alerts)} alertas enviados")
        except Exception as e:
            logger.error(f"Erro ao carregar estado: {e}")
            
    def save_state(self):
        """Salva estado atual do monitoramento"""
        try:
            state = {
                'last_position': self.last_position,
                'sent_alerts': list(self.sent_alerts),
                'last_update': datetime.now().isoformat()
            }
            with open(STATE_FILE, 'w') as f:
                json.dump(state, f, indent=2)
        except Exception as e:
            logger.error(f"Erro ao salvar estado: {e}")
            
    def send_email(self, subject, body, alert_id):
        """Envia email de alerta"""
        if alert_id in self.sent_alerts:
            logger.info(f"Alerta {alert_id} já foi enviado, ignorando")
            return False
            
        try:
            # Verifica se temos configuração de email
            if not self.config['sender_password']:
                logger.warning("Email não configurado, apenas logando o alerta")
                logger.warning(f"ALERTA: {subject}")
                logger.warning(f"DETALHES: {body}")
                return False
                
            msg = MIMEMultipart()
            msg['From'] = self.config['sender_email']
            msg['To'] = self.config['recipient_email']
            msg['Subject'] = f"[SIMIR ALERT] {subject}"
            
            # Corpo do email
            email_body = f"""
ALERTA DE SEGURANÇA - SIMIR
============================

{body}

Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Sistema: SIMIR - Sonda Inteligente de Monitoramento Interno da Rede

Este é um alerta automático gerado pelo sistema SIMIR.
Para mais informações, verifique os logs do sistema.
"""
            
            msg.attach(MIMEText(email_body, 'plain'))
            
            # Conectar e enviar
            server = smtplib.SMTP(self.config['smtp_server'], self.config['smtp_port'])
            server.starttls()
            server.login(self.config['sender_email'], self.config['sender_password'])
            
            text = msg.as_string()
            server.sendmail(self.config['sender_email'], self.config['recipient_email'], text)
            server.quit()
            
            logger.info(f"Email enviado com sucesso para {self.config['recipient_email']}")
            self.sent_alerts.add(alert_id)
            return True
            
        except Exception as e:
            logger.error(f"Erro ao enviar email: {e}")
            return False
            
    def parse_notice_line(self, line):
        """Parse de linha do notice.log"""
        try:
            # Zeek logs podem ser TSV ou JSON
            if line.startswith('{'):
                # JSON format
                data = json.loads(line)
            else:
                # TSV format
                fields = line.strip().split('\t')
                if len(fields) < 6:
                    return None
                    
                data = {
                    'ts': fields[0],
                    'note': fields[4] if len(fields) > 4 else '',
                    'msg': fields[5] if len(fields) > 5 else '',
                    'src': fields[2] if len(fields) > 2 else '',
                    'dst': fields[3] if len(fields) > 3 else ''
                }
                
            return data
        except Exception as e:
            logger.debug(f"Erro ao parsear linha: {e}")
            return None
            
    def process_notice(self, notice_data):
        """Processa um notice e verifica se deve enviar alerta"""
        try:
            note_type = notice_data.get('note', '')
            message = notice_data.get('msg', '')
            src_ip = notice_data.get('src', '')
            timestamp = notice_data.get('ts', '')
            
            # Verifica se é um alerta de port scan
            port_scan_indicators = [
                'Port_Scan',
                'Port_Scan_Target', 
                'Closed_Port_Access',
                'port scan',
                'port scanning',
                'scan detected'
            ]
            
            is_port_scan = any(indicator.lower() in note_type.lower() or 
                             indicator.lower() in message.lower() 
                             for indicator in port_scan_indicators)
            
            if is_port_scan:
                # Cria ID único para o alerta
                alert_id = f"{note_type}_{src_ip}_{timestamp}"
                
                # Prepara dados do alerta
                subject = f"Port Scan Detectado - {src_ip}"
                body = f"""
DETECÇÃO DE PORT SCAN
====================

Tipo de Alerta: {note_type}
IP de Origem: {src_ip}
Timestamp: {datetime.fromtimestamp(float(timestamp)).strftime('%Y-%m-%d %H:%M:%S')}

Detalhes: {message}

AÇÃO RECOMENDADA:
- Verificar se o IP {src_ip} é legítimo
- Analisar logs detalhados no sistema
- Considerar bloqueio se for atividade maliciosa
"""
                
                logger.info(f"Port scan detectado: {message}")
                return self.send_email(subject, body, alert_id)
                
        except Exception as e:
            logger.error(f"Erro ao processar notice: {e}")
            
        return False
        
    def monitor_logs(self):
        """Monitora continuamente os logs do Zeek"""
        logger.info("Iniciando monitoramento de logs do Zeek...")
        
        while True:
            try:
                if not os.path.exists(NOTICE_LOG_FILE):
                    logger.debug(f"Arquivo {NOTICE_LOG_FILE} não existe ainda")
                    time.sleep(10)
                    continue
                    
                with open(NOTICE_LOG_FILE, 'r') as f:
                    # Move para a última posição lida
                    f.seek(self.last_position)
                    
                    lines_processed = 0
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith('#'):
                            continue
                            
                        notice_data = self.parse_notice_line(line)
                        if notice_data:
                            self.process_notice(notice_data)
                            lines_processed += 1
                    
                    # Atualiza posição
                    self.last_position = f.tell()
                    
                    if lines_processed > 0:
                        logger.info(f"Processadas {lines_processed} novas linhas de log")
                        self.save_state()
                        
            except FileNotFoundError:
                logger.debug("Arquivo de log não encontrado, aguardando...")
            except Exception as e:
                logger.error(f"Erro no monitoramento: {e}")
                
            time.sleep(5)  # Verifica logs a cada 5 segundos

def main():
    parser = argparse.ArgumentParser(description='Monitor de Port Scan SIMIR')
    parser.add_argument('--email-password', help='Senha do email para envio de alertas')
    parser.add_argument('--test', action='store_true', help='Envia email de teste')
    parser.add_argument('--daemon', action='store_true', help='Executa como daemon')
    
    args = parser.parse_args()
    
    # Configura senha do email se fornecida
    if args.email_password:
        EMAIL_CONFIG['sender_password'] = args.email_password
    elif 'SIMIR_EMAIL_PASSWORD' in os.environ:
        EMAIL_CONFIG['sender_password'] = os.environ['SIMIR_EMAIL_PASSWORD']
    
    monitor = PortScanMonitor(EMAIL_CONFIG)
    
    if args.test:
        logger.info("Enviando email de teste...")
        success = monitor.send_email(
            "Teste do Sistema SIMIR", 
            "Este é um email de teste do sistema de monitoramento SIMIR.\n\nSe você recebeu este email, o sistema está funcionando corretamente!",
            f"test_{datetime.now().timestamp()}"
        )
        if success:
            print("✓ Email de teste enviado com sucesso!")
        else:
            print("✗ Falha ao enviar email de teste")
        return
    
    if args.daemon:
        logger.info("Executando como daemon...")
        
    try:
        monitor.monitor_logs()
    except KeyboardInterrupt:
        logger.info("Monitoramento interrompido pelo usuário")
    except Exception as e:
        logger.error(f"Erro crítico: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
