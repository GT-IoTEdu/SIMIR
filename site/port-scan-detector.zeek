# Script Zeek para detecção de port scan
# Detecta tentativas de port scan e gera alertas

@load base/frameworks/notice
@load base/protocols/conn
@load ./simir-notice-standards.zeek

module PortScan;

export {
    # Tipos de notice para port scan
    redef enum Notice::Type += {
        ## Indica que um host está fazendo port scan
        Port_Scan,
        ## Indica que um host está sendo alvo de port scan
        Port_Scan_Target,
        ## Tentativa de conexão em porta fechada
        Closed_Port_Access
    };

    # Configurações ajustadas para reduzir falsos positivos
    global port_scan_threshold = 20 &redef;          # Portas distintas totais antes de alertar
    global vertical_port_threshold = 12 &redef;      # Portas distintas contra um mesmo host
    global horizontal_host_threshold = 10 &redef;    # Hosts distintos sondados na mesma porta
    global failed_ratio_threshold = 0.6 &redef;      # Percentual mínimo de falhas para confirmar scan
    global min_total_connections = 20 &redef;        # Mínimo de conexões para avaliação ampla
    global time_window = 10min &redef;              # Janela de tempo para análise
    global closed_port_threshold = 8 &redef;        # Tentativas falhas antes do alerta
}

# Estrutura para rastrear tentativas de conexão
type scan_tracker: record {
    hosts: set[addr] &default=set();
    ports: set[port] &default=set();
    total_connections: count &default=0;
    failed_connections: count &default=0;
    first_seen: time;
    last_seen: time;
};

# Tabelas para rastrear atividade
global scanners: table[addr] of scan_tracker &create_expire=time_window;
global targets: table[addr] of scan_tracker &create_expire=time_window;

# Rastros específicos para identificar varreduras verticais e horizontais
global host_port_activity: table[addr, addr] of set[port] &create_expire=time_window;
global port_host_activity: table[addr, port] of set[addr] &create_expire=time_window;

# Estados de conexão considerados como falha para cálculo de acurácia
const failure_states: set[string] = set("S0", "S1", "S2", "S3", "REJ", "RSTO", "RSTR", "RSTOS0", "RSTRH", "SH", "SHR", "OTH") &redef;

function is_failed_connection(c: connection): bool
{
    if (! c?$conn || ! c$conn?$conn_state)
        return F;

    return c$conn$conn_state in failure_states;
}

# Whitelist de IPs legítimos (evita falsos positivos)
global whitelist_ips: set[addr] = {
    127.0.0.1,      # Localhost IPv4
    [::1],          # Localhost IPv6 
    192.168.0.1,    # Gateway típico
    192.168.1.1,    # Gateway típico
    10.0.0.1,       # Gateway típico
} &redef;

# Subnets para ignorar (redes locais comuns)
global ignore_subnets: set[subnet] = {
    224.0.0.0/4,    # Multicast
    169.254.0.0/16, # Link-local
    255.255.255.255/32, # Broadcast
} &redef;

# Função para detectar port scan baseado em conexões
event connection_state_remove(c: connection)
{
    local orig = c$id$orig_h;
    local dest = c$id$resp_h;
    local dest_port = c$id$resp_p;
    local now = network_time();

    # Ignora tráfego local (mesmo host)
    if (orig == dest)
        return;

    # Ignora IPs na whitelist
    if (orig in whitelist_ips || dest in whitelist_ips)
        return;

    # Ignora subnets multicast e broadcast
    if (orig in ignore_subnets || dest in ignore_subnets)
        return;

    # Ignora endereços privados fazendo conexões para a internet
    if (Site::is_private_addr(orig) && !Site::is_private_addr(dest))
        return;

    # Inicializa tracker para scanner se não existir
    if (orig !in scanners) {
        scanners[orig] = [$first_seen=now, $last_seen=now];
    }

    # Inicializa tracker para target se não existir
    if (dest !in targets) {
        targets[dest] = [$first_seen=now, $last_seen=now];
    }

    local connection_failed = is_failed_connection(c);

    # Atualiza informações do scanner
    local scanner = scanners[orig];
    add scanner$hosts[dest];
    add scanner$ports[dest_port];
    ++scanner$total_connections;
    if (connection_failed)
        ++scanner$failed_connections;
    scanner$last_seen = now;

    # Atualiza informações do target
    local target = targets[dest];
    add target$hosts[orig];
    add target$ports[dest_port];
    ++target$total_connections;
    if (connection_failed)
        ++target$failed_connections;
    target$last_seen = now;

    # Mapeia varreduras verticais (mesmo host, portas diferentes)
    if ([orig, dest] !in host_port_activity)
        host_port_activity[orig, dest] = set();
    add host_port_activity[orig, dest][dest_port];

    # Mapeia varreduras horizontais (mesma porta, múltiplos hosts)
    if ([orig, dest_port] !in port_host_activity)
        port_host_activity[orig, dest_port] = set();
    add port_host_activity[orig, dest_port][dest];

    local failure_ratio = 0.0;
    if (scanner$total_connections > 0)
        failure_ratio = scanner$failed_connections * 1.0 / scanner$total_connections;

    # Port scan amplo (varredura geral)
    if (scanner$total_connections >= min_total_connections &&
        |scanner$ports| >= port_scan_threshold &&
        failure_ratio >= failed_ratio_threshold) {

        NOTICE([$note=Port_Scan,
                $msg=SIMIR::format_portscan_message("WIDE_SCAN", orig,
                        fmt("Varredura ampla: %d portas em %d hosts | Conexões: %d | Falhas: %.0f%% | Janela: %s",
                            |scanner$ports|, |scanner$hosts|, scanner$total_connections,
                            failure_ratio * 100.0,
                            duration_to_mins_secs(scanner$last_seen - scanner$first_seen))),
                $src=orig,
                $identifier=cat(orig, "wide_scan")]);
    }

    # Varredura vertical (múltiplas portas em um mesmo alvo)
    if (connection_failed && [orig, dest] in host_port_activity) {
        local vertical_count = |host_port_activity[orig, dest]|;
        if (vertical_count >= vertical_port_threshold && failure_ratio >= failed_ratio_threshold) {
            NOTICE([$note=Port_Scan,
                    $msg=SIMIR::format_portscan_message("VERTICAL", orig,
                            fmt("Varredura vertical contra %s: %d portas sondadas (limite %d) | Falhas: %.0f%%",
                                SIMIR::format_ip(dest), vertical_count, vertical_port_threshold,
                                failure_ratio * 100.0)),
                    $src=orig,
                    $dst=dest,
                    $identifier=cat(orig, dest, "vertical_scan")]);
        }
    }

    # Varredura horizontal (mesma porta em diversos hosts)
    if (connection_failed && [orig, dest_port] in port_host_activity) {
        local horizontal_count = |port_host_activity[orig, dest_port]|;
        if (horizontal_count >= horizontal_host_threshold && failure_ratio >= failed_ratio_threshold) {
            NOTICE([$note=Port_Scan,
                    $msg=SIMIR::format_portscan_message("HORIZONTAL", orig,
                            fmt("Varredura horizontal na porta %s: %d hosts sondados (limite %d) | Falhas: %.0f%%",
                                port_to_count(dest_port), horizontal_count, horizontal_host_threshold,
                                failure_ratio * 100.0)),
                    $src=orig,
                    $dst=dest,
                    $identifier=cat(orig, port_to_count(dest_port), "horizontal_scan")]);
        }
    }

    # Tentativas repetidas em portas fechadas
    if (connection_failed && scanner$failed_connections >= closed_port_threshold) {
        NOTICE([$note=Closed_Port_Access,
                $msg=SIMIR::format_portscan_message("FAILED_PROBING", orig,
                        fmt("Tentativas em portas fechadas: %d falhas (total %d conexões)",
                            scanner$failed_connections, scanner$total_connections)),
                $src=orig,
                $identifier=cat(orig, "closed_ports")]);
    }

    # Host alvo recebendo varredura de múltiplas fontes
    local target_failure_ratio = 0.0;
    if (target$total_connections > 0)
        target_failure_ratio = target$failed_connections * 1.0 / target$total_connections;

    if ((|target$hosts| >= horizontal_host_threshold ||
         |target$ports| >= vertical_port_threshold) &&
        target_failure_ratio >= failed_ratio_threshold) {
        NOTICE([$note=Port_Scan_Target,
                $msg=SIMIR::format_portscan_message("TARGETED", dest,
                        fmt("Host alvo de varredura: %d fontes distintas, %d portas sondadas | Falhas: %.0f%%",
                            |target$hosts|, |target$ports|, target_failure_ratio * 100.0)),
                $src=dest,
                $identifier=cat(dest, "target_scan")]);
    }
}

# Event para limpar dados antigos
event zeek_init()
{
    print fmt("Port Scan Detection ativo - thresholds: geral=%d portas, vertical=%d portas, horizontal=%d hosts, falha mínima=%.0f%%, janela=%s", 
              port_scan_threshold, vertical_port_threshold, horizontal_host_threshold,
              failed_ratio_threshold * 100.0, time_window);
}
