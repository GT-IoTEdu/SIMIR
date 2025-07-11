FROM zeek/zeek:latest

# Instala dependências essenciais, incluindo gettext (para envsubst)
RUN apt-get update && apt-get install -y --no-install-recommends \
    g++ cmake make sendmail libpcap-dev iproute2 net-tools gdb nano curl nano gettext \
 && rm -rf /var/lib/apt/lists/*

# Copia scripts personalizados
COPY site/ /usr/local/zeek/share/zeek/site/

# Copia e ajusta script de entrada
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Define diretório de trabalho
WORKDIR /usr/local/zeek

# Expõe portas comuns
EXPOSE 47760 47761

# Define o entrypoint
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
