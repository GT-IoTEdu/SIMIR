# Configuração básica do Zeek
@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/http
@load base/frameworks/notice

# CORREÇÃO CRÍTICA: Ignora checksums inválidos devido a checksum offloading
# Resolve problema onde Zeek descarta pacotes com checksums incorretos
redef ignore_checksums = T;

# Carrega padrões de mensagens
@load ./simir-notice-standards.zeek

# Carrega detectores personalizados
# Use @load ./intel-debug.zeek para modo diagnóstico simplificado
@load ./port-scan-detector.zeek
@load ./brute-force-detector.zeek
@load ./intelligence-framework.zeek
@load ./ddos-detector.zeek

# Configurações de logging
# Usar formato padrão TSV do Zeek ao invés de JSON para compatibilidade
# redef LogAscii::use_json = T;

# Configuração para garantir que todos os notices sejam logados
hook Notice::policy(n: Notice::Info) &priority=10
{
    # Força log para todos os notices
    add n$actions[Notice::ACTION_LOG];
}

# Configuração adicional removida devido a incompatibilidade
