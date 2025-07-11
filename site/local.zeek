# Configuração básica do Zeek
@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/http
@load base/frameworks/notice

# Carrega detector de port scan personalizado
@load ./port-scan-detector.zeek

# Configurações de logging
redef LogAscii::use_json = T;

# Configurações para Notice (alertas)
# Habilita logs de notice para todos os alertas
redef Notice::policy += {
    [$pred(n: Notice::Info) = { return T; },
     $action = Notice::ACTION_LOG]
};
