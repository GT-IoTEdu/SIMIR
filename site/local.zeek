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
# Garante que ALL os notices sejam logados
hook Notice::policy(n: Notice::Info)
{
    # Força log para todos os notices
    add n$actions[Notice::ACTION_LOG];
    
    # Garante que o arquivo notice.log seja sempre criado
    if (|n$actions| == 0)
        add n$actions[Notice::ACTION_LOG];
}

# Configuração adicional removida devido a incompatibilidade
