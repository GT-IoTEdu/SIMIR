#!/bin/bash
set -e

# Função para verificar saúde do sistema
check_system_health() {
    echo "[Zeek Entrypoint] Verificando saúde do sistema..."
    
    # Verifica se temos permissões adequadas
    if [ "$(id -u)" -ne 0 ]; then
        echo "[Zeek Entrypoint] AVISO: Não executando como root. Isso pode causar problemas."
    fi
    
    # Verifica se o zeek está instalado e funcionando
    if ! command -v zeek >/dev/null 2>&1; then
        echo "[Zeek Entrypoint] ERRO: Comando zeek não encontrado!"
        exit 1
    fi
    
    if ! command -v zeekctl >/dev/null 2>&1; then
        echo "[Zeek Entrypoint] ERRO: Comando zeekctl não encontrado!"
        exit 1
    fi
    
    echo "[Zeek Entrypoint] Versão do Zeek: $(zeek --version 2>/dev/null || echo 'Não foi possível obter a versão')"
}

# Executa verificação de saúde
check_system_health

IFACE="${ZEEK_INTERFACE:-enx000ec89f6cc0}"
echo "[Zeek Entrypoint] Interface: $IFACE"

# Verifica se a interface existe e está configurada corretamente
echo "[Zeek Entrypoint] Verificando interface de rede..."
if ! /usr/local/bin/check-interface.sh "$IFACE"; then
    echo "[Zeek Entrypoint] ERRO: Problemas com a interface $IFACE"
    exit 1
fi

mkdir -p /usr/local/zeek/etc
mkdir -p /usr/local/zeek/spool/zeek
chmod 777 /usr/local/zeek/etc
chmod 777 /usr/local/zeek/spool

# Configura permissões do sistema
echo "[Zeek Entrypoint] Configurando permissões do sistema..."
/usr/local/bin/setup-permissions.sh

# Inicializa zeekctl se necessário
if [ ! -f /usr/local/zeek/etc/zeekctl.cfg ]; then
    echo "[Zeek Entrypoint] Rodando zeekctl setup para criar zeekctl.cfg..."
    zeekctl setup --debug 2>&1 || {
        echo "[Zeek Entrypoint] ERRO ao rodar zeekctl setup!";
        echo "[Zeek Entrypoint] Conteúdo do diretório /usr/local/zeek/etc:";
        ls -la /usr/local/zeek/etc;
        echo "[Zeek Entrypoint] Verificando permissões:";
        ls -la /usr/local/zeek/;
        exit 1;
    }
fi

# Verifica se zeekctl.cfg foi criado
if [ ! -f /usr/local/zeek/etc/zeekctl.cfg ]; then
    echo "[Zeek Entrypoint] ERRO: zeekctl.cfg não foi criado após setup!"
    exit 1
fi

# Gera node.cfg dinamicamente
echo "[Zeek Entrypoint] Criando node.cfg com interface $IFACE..."
cat <<EOF > /usr/local/zeek/etc/node.cfg
[zeek]
type=standalone
host=localhost
interface=$IFACE
EOF

# Verifica se node.cfg foi criado corretamente
if [ ! -f /usr/local/zeek/etc/node.cfg ]; then
    echo "[Zeek Entrypoint] ERRO: Falha ao criar node.cfg!"
    exit 1
fi

echo "[Zeek Entrypoint] Conteúdo do node.cfg:"
cat /usr/local/zeek/etc/node.cfg

# Para qualquer instância do Zeek que possa estar rodando
echo "[Zeek Entrypoint] Parando instâncias anteriores do Zeek..."
zeekctl stop 2>/dev/null || true
zeekctl cleanup 2>/dev/null || true

# Aguarda um pouco para garantir que tudo parou
sleep 2

echo "[Zeek Entrypoint] Iniciando deploy do Zeek..."
if ! zeekctl deploy 2>&1; then
    echo "[Zeek Entrypoint] ERRO ao rodar zeekctl deploy!";
    echo "[Zeek Entrypoint] Verificando logs de erro...";
    if [ -f /usr/local/zeek/spool/zeek/zeekctl.err ]; then
        echo "[Zeek Entrypoint] Conteúdo do zeekctl.err:";
        cat /usr/local/zeek/spool/zeek/zeekctl.err;
    fi
    echo "[Zeek Entrypoint] Status dos nós:";
    zeekctl status 2>&1 || true
    echo "[Zeek Entrypoint] Listando arquivos no spool:";
    ls -la /usr/local/zeek/spool/zeek/ 2>/dev/null || true
    exit 1
fi

echo "[Zeek Entrypoint] Deploy realizado com sucesso!"
echo "[Zeek Entrypoint] Status dos nós:"
zeekctl status

# Procura por qualquer arquivo de log nos locais possíveis
echo "[Zeek Entrypoint] Procurando arquivos de log do Zeek..."
TRIES=0
LOGFILE=""

while [ -z "$LOGFILE" ] && [ $TRIES -lt 30 ]; do
    echo "[Zeek Entrypoint] Tentativa $TRIES/30 - Procurando arquivos de log..."
    
    # Procura por conn.log primeiro (preferido)
    FOUND_CONN=$(find /usr/local/zeek/spool/zeek/ -name "conn.log" -type f 2>/dev/null | head -1)
    if [ -n "$FOUND_CONN" ] && [ -s "$FOUND_CONN" ]; then
        LOGFILE="$FOUND_CONN"
        echo "[Zeek Entrypoint] ✓ Encontrado conn.log em: $LOGFILE"
        break
    fi
    
    # Se conn.log não existir, procura por outros logs importantes
    for log_name in "loaded_scripts.log" "packet_filter.log" "dns.log" "http.log" "ssl.log"; do
        FOUND_LOG=$(find /usr/local/zeek/spool/zeek/ -name "$log_name" -type f 2>/dev/null | head -1)
        if [ -n "$FOUND_LOG" ] && [ -s "$FOUND_LOG" ]; then
            LOGFILE="$FOUND_LOG"
            echo "[Zeek Entrypoint] ✓ Encontrado $log_name em: $LOGFILE"
            break 2
        fi
    done
    
    # Se nenhum log específico for encontrado, pega qualquer .log
    if [ -z "$LOGFILE" ]; then
        FOUND_ANY=$(find /usr/local/zeek/spool/zeek/ -name "*.log" -type f -size +0c 2>/dev/null | head -1)
        if [ -n "$FOUND_ANY" ]; then
            LOGFILE="$FOUND_ANY"
            echo "[Zeek Entrypoint] ✓ Encontrado arquivo de log: $LOGFILE"
            break
        fi
    fi
    
    sleep 3
    TRIES=$((TRIES+1))
    
    # Verifica se o processo zeek ainda está rodando
    if [ $TRIES -eq 5 ] || [ $TRIES -eq 15 ] || [ $TRIES -eq 25 ]; then
        echo "[Zeek Entrypoint] === Status após $TRIES tentativas ==="
        zeekctl status 2>&1 || true
        echo "[Zeek Entrypoint] Arquivos no spool:"
        ls -la /usr/local/zeek/spool/zeek/ 2>/dev/null | grep -E "\.(log|txt)$" || echo "Nenhum arquivo de log encontrado ainda"
        echo "[Zeek Entrypoint] ================================="
    fi
done

if [ -z "$LOGFILE" ]; then
    echo "[Zeek Entrypoint] ⚠ Nenhum arquivo de log foi encontrado após 30 tentativas."
    echo "[Zeek Entrypoint] Isso pode ser normal se não houver tráfego de rede."
    echo
    echo "[Zeek Entrypoint] Status final dos nós:"
    zeekctl status 2>&1 || true
    echo
    echo "[Zeek Entrypoint] Todos os arquivos no spool:"
    ls -la /usr/local/zeek/spool/zeek/ 2>/dev/null || true
    echo
    echo "[Zeek Entrypoint] O Zeek continuará rodando. Para gerar logs:"
    echo "1. Conecte um dispositivo na rede monitorada"
    echo "2. Gere tráfego de rede (navegação, ping, etc.)"
    echo "3. Use 'docker exec -it SIMIR_Z ls -la /usr/local/zeek/spool/zeek/' para verificar logs"
    echo
    echo "[Zeek Entrypoint] Mantendo container ativo e monitorando diretório de logs..."
    
    # Monitora o diretório de logs em vez de um arquivo específico
    while true; do
        sleep 30
        NEW_LOGS=$(find /usr/local/zeek/spool/zeek/ -name "*.log" -type f -size +0c 2>/dev/null)
        if [ -n "$NEW_LOGS" ]; then
            echo "[Zeek Entrypoint] 🎉 Novos logs detectados!"
            echo "$NEW_LOGS"
            LOGFILE=$(echo "$NEW_LOGS" | head -1)
            break
        fi
        echo "[Zeek Entrypoint] $(date): Aguardando tráfego de rede para gerar logs..."
    done
fi

# Iniciar sistema SIMIR se disponível
if [ -f "/usr/local/bin/simir-autostart.sh" ]; then
    echo "[Zeek Entrypoint] � Iniciando sistema SIMIR de monitoramento..."
    
    # Copia scripts SIMIR para locais padrão
    mkdir -p /opt/simir/scripts
    mkdir -p /opt/simir/config
    
    if [ -f "/usr/local/bin/simir-monitor.py" ]; then
        cp /usr/local/bin/simir-monitor.py /opt/simir/scripts/
        chmod +x /opt/simir/scripts/simir-monitor.py
    fi
    
    # Inicia SIMIR em background
    /usr/local/bin/simir-autostart.sh auto-start &
    SIMIR_PID=$!
    
    echo "[Zeek Entrypoint] ✓ Sistema SIMIR iniciado (PID: $SIMIR_PID)"
else
    echo "[Zeek Entrypoint] ⚠ Sistema SIMIR não encontrado, prosseguindo apenas com Zeek"
fi

echo "[Zeek Entrypoint] �📊 Monitorando arquivo de log: $LOGFILE"
echo "[Zeek Entrypoint] 🔍 Sistema SIMIR ativo para detecção de port scan"
echo "[Zeek Entrypoint] Use Ctrl+C para parar o monitoramento"

# Função para shutdown gracioso
graceful_shutdown() {
    echo "[Zeek Entrypoint] Recebido sinal de shutdown..."
    
    # Para sistema SIMIR se estiver rodando
    if [ -n "$SIMIR_PID" ] && kill -0 "$SIMIR_PID" 2>/dev/null; then
        echo "[Zeek Entrypoint] Parando sistema SIMIR..."
        kill "$SIMIR_PID" 2>/dev/null || true
    fi
    
    if [ -f "/usr/local/bin/simir-autostart.sh" ]; then
        /usr/local/bin/simir-autostart.sh stop 2>/dev/null || true
    fi
    
    # Para Zeek
    echo "[Zeek Entrypoint] Parando Zeek graciosamente..."
    zeekctl stop 2>/dev/null || true
    zeekctl cleanup 2>/dev/null || true
    
    echo "[Zeek Entrypoint] Shutdown concluído."
    exit 0
}

# Configura trap para shutdown gracioso
trap graceful_shutdown SIGTERM SIGINT

# Monitora logs e mantém container ativo
tail -F "$LOGFILE"