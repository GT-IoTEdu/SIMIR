#!/bin/bash
set -e

IFACE="${ZEEK_INTERFACE:-enx000ec89f6cc0}"
echo "[Zeek Entrypoint] Interface: $IFACE"

mkdir -p /usr/local/zeek/etc
chmod 777 /usr/local/zeek/etc

# Inicializa zeekctl se necessário
if [ ! -f /usr/local/zeek/etc/zeekctl.cfg ]; then
    echo "[Zeek Entrypoint] Rodando zeekctl setup para criar zeekctl.cfg..."
    zeekctl setup --debug || {
        echo "[Zeek Entrypoint] ERRO ao rodar zeekctl setup!";
        ls -l /usr/local/zeek/etc;
        exit 1;
    }
fi

# Gera node.cfg dinamicamente
cat <<EOF > /usr/local/zeek/etc/node.cfg
[zeek]
type=standalone
host=localhost
interface=$IFACE
EOF

zeekctl stop
zeekctl cleanup
if ! zeekctl deploy; then
    echo "[Zeek Entrypoint] ERRO ao rodar zeekctl deploy!";
    if [ -f /usr/local/zeek/spool/zeek/zeekctl.err ]; then
        cat /usr/local/zeek/spool/zeek/zeekctl.err;
    fi
    exit 1
fi

LOGFILE="/usr/local/zeek/spool/zeek/current/conn.log"
TRIES=0
while [ ! -f "$LOGFILE" ] && [ $TRIES -lt 10 ]; do
    echo "[Zeek Entrypoint] Aguardando criação do $LOGFILE... ($TRIES)"
    sleep 2
    TRIES=$((TRIES+1))
done

if [ ! -f "$LOGFILE" ]; then
    echo "[Zeek Entrypoint] ERRO: $LOGFILE não foi criado. Veja os logs acima."
    exit 2
fi

tail -F $LOGFILE