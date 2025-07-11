FROM zeek/zeek:latest

# Instala dependências essenciais, incluindo Python e utilitários para SIMIR
RUN apt-get update && apt-get install -y --no-install-recommends \
    g++ cmake make sendmail libpcap-dev iproute2 net-tools gdb nano curl gettext \
    python3 python3-pip nmap \
 && rm -rf /var/lib/apt/lists/*

# Copia scripts personalizados Zeek
COPY site/ /usr/local/zeek/share/zeek/site/

# Copia scripts SIMIR
COPY scripts/entrypoint.sh /usr/local/bin/entrypoint.sh
COPY scripts/check-interface.sh /usr/local/bin/check-interface.sh
COPY scripts/setup-permissions.sh /usr/local/bin/setup-permissions.sh
COPY scripts/simir-monitor.py /usr/local/bin/simir-monitor.py
COPY scripts/simir-autostart.sh /usr/local/bin/simir-autostart.sh

# Define permissões para todos os scripts
RUN chmod +x /usr/local/bin/entrypoint.sh \
    /usr/local/bin/check-interface.sh \
    /usr/local/bin/setup-permissions.sh \
    /usr/local/bin/simir-monitor.py \
    /usr/local/bin/simir-autostart.sh

# Cria diretórios para SIMIR
RUN mkdir -p /opt/simir/scripts /opt/simir/config /var/log/simir

# Define diretório de trabalho
WORKDIR /usr/local/zeek

# Expõe portas comuns
EXPOSE 47760 47761

# Define o entrypoint
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
