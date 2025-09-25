# Configuração básica do Zeek
@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/http
@load base/frameworks/notice

# CORREÇÃO CRÍTICA: Ignora checksums inválidos devido a checksum offloading
# Resolve problema onde Zeek descarta pacotes com checksums incorretos
redef ignore_checksums = T;

# Carrega detectores personalizados
@load ./port-scan-detector.zeek
@load ./brute-force-detector.zeek
@load ./intelligence-framework.zeek

# Configurações de logging
redef LogAscii::use_json = T;

# Configurações para Notice (alertas)
# Habilita logs de notice para todos os alertas
hook Notice::policy(n: Notice::Info)
{
    add n$actions[Notice::ACTION_LOG];
}
