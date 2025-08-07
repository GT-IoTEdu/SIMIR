# Configuração básica do Zeek
@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/http
@load base/frameworks/notice

# Carrega detectores personalizados
@load ./port-scan-detector.zeek
@load ./brute-force-detector.zeek

# Configurações de logging
redef LogAscii::use_json = T;

# Configurações para Notice (alertas)
# Habilita logs de notice para todos os alertas
hook Notice::policy(n: Notice::Info)
{
    add n$actions[Notice::ACTION_LOG];
}
