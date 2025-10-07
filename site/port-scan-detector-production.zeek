# Port Scan Detector - Versão Produção Anti-Falsos-Positivos
# Detecta tentativas de port scan com alta precisão

@load base/frameworks/notice
@load base/protocols/conn
@load ./simir-notice-standards.zeek

module PortScan;

export {
    # Tipos de notice para port scan
    redef enum Notice::Type += {
        Port_Scan_Detected,
        Port_Scan_Target,
        Closed_Port_Access,
        Stealth_Scan_Detected,
        Service_Discovery_Scan
    };

    # Configurações otimizadas para reduzir falsos positivos
    global port_scan_threshold = 20;         # Mais restritivo
    global time_window = 15min;              # Janela maior para análise
    global closed_port_threshold = 15;       # Mais tentativas antes de alertar
    global host_threshold = 8;               # Mais hosts para scan vertical
    global connection_rate_threshold = 5.0;  # Conexões por segundo
    global legitimate_services_threshold = 3; # Serviços legítimos antes de marcar como scan
    
    # Configuração de produção
    global production_mode: bool = T &redef;
    global enable_whitelist: bool = T &redef;
}

# Estrutura avançada para rastrear tentativas
type advanced_scan_tracker: record {
    hosts: set[addr] &default=set();
    ports: set[port] &default=set();
    successful_connections: count &default=0;
    failed_connections: count &default=0;
    total_connections: count &default=0;
    first_seen: time;
    last_seen: time;
    connection_states: set[string] &default=set();
    services_detected: set[string] &default=set();
    avg_connection_duration: double &default=0.0;
    is_likely_legitimate: bool &default=F;
};

# Tabelas para rastreamento avançado
global scanners: table[addr] of advanced_scan_tracker &create_expire=time_window;
global targets: table[addr] of advanced_scan_tracker &create_expire=time_window;

# Whitelist expandida e inteligente
global whitelist_ips: set[addr] = {
    127.0.0.1,      # Localhost IPv4
    [::1],          # Localhost IPv6
} &redef;

# Serviços automatizados legítimos (reduz falsos positivos)
global legitimate_automated_services: set[port] = {
    80/tcp, 443/tcp,    # HTTP/HTTPS
    53/tcp, 53/udp,     # DNS
    25/tcp, 587/tcp,    # SMTP
    110/tcp, 143/tcp,   # POP3/IMAP
    993/tcp, 995/tcp,   # IMAPS/POP3S
    21/tcp,             # FTP
    22/tcp,             # SSH
} &redef;

# Subnets para monitoramento específico
global monitor_subnets: set[subnet] = {
    192.168.0.0/16,     # RFC 1918
    172.16.0.0/12,      # RFC 1918  
    10.0.0.0/8,         # RFC 1918
} &redef;

# Subnets para ignorar completamente
global ignore_subnets: set[subnet] = {
    224.0.0.0/4,        # Multicast
    169.254.0.0/16,     # Link-local
    255.255.255.255/32, # Broadcast
    0.0.0.0/32,         # Invalid
    fe80::/10,          # IPv6 Link-local
    ff00::/8,           # IPv6 Multicast
} &redef;

# Função para determinar se uma conexão é suspeita
function is_suspicious_connection(c: connection): bool
{
    # Conexão muito rápida (possível scan)
    if (c?$duration && c$duration < 0.1sec)
        return T;
        
    # Estados de conexão que indicam scan
    if (c?$conn && c$conn?$conn_state) {
        if (c$conn$conn_state in set("REJ", "S0", "RSTO", "RSTR"))
            return T;
    }
    
    # Sem dados transferidos (típico de scan)
    if (c?$orig && c$orig?$size && c$orig$size == 0)
        return T;
        
    return F;
}

# Função para detectar padrões legítimos
function analyze_legitimacy(tracker: advanced_scan_tracker): bool
{
    # Se há muitas conexões bem-sucedidas, provavelmente é legítimo
    local success_rate = tracker$successful_connections / (tracker$total_connections * 1.0);
    if (success_rate > 0.6)
        return T;
        
    # Se está conectando a serviços comuns, pode ser legítimo
    local common_services = 0;
    for (port in tracker$ports) {
        if (port in legitimate_automated_services)
            ++common_services;
    }
    
    if (common_services >= legitimate_services_threshold && |tracker$ports| <= 10)
        return T;
        
    # Se a taxa de conexão é baixa, pode ser atividade normal
    local duration = tracker$last_seen - tracker$first_seen;
    local connection_rate = tracker$total_connections / duration;
    if (connection_rate < connection_rate_threshold && tracker$total_connections < 50)
        return T;
        
    return F;
}

# Evento principal de análise de conexão
event connection_state_remove(c: connection)
{
    local orig = c$id$orig_h;
    local dest = c$id$resp_h;
    local dest_port = c$id$resp_p;
    
    # Filtros básicos
    if (orig == dest) return;
    if (enable_whitelist && (orig in whitelist_ips || dest in whitelist_ips)) return;
    if (orig in ignore_subnets || dest in ignore_subnets) return;
    
    # Em modo produção, foca apenas em subnets monitoradas
    if (production_mode) {
        local monitor_orig = F;
        local monitor_dest = F;
        
        for (subnet in monitor_subnets) {
            if (orig in subnet) monitor_orig = T;
            if (dest in subnet) monitor_dest = T;
        }
        
        # Pelo menos um dos IPs deve estar na rede monitorada
        if (!monitor_orig && !monitor_dest) return;
    }
    
    # Inicializa trackers
    if (orig !in scanners) {
        scanners[orig] = [$first_seen=network_time(), $last_seen=network_time()];
    }
    
    if (dest !in targets) {
        targets[dest] = [$first_seen=network_time(), $last_seen=network_time()];
    }
    
    # Atualiza informações do scanner
    local scanner = scanners[orig];
    add scanner$hosts[dest];
    add scanner$ports[dest_port];
    ++scanner$total_connections;
    scanner$last_seen = network_time();
    
    # Analisa estado da conexão
    if (c?$conn && c$conn?$conn_state) {
        add scanner$connection_states[c$conn$conn_state];
        
        if (c$conn$conn_state == "SF" || c$conn$conn_state == "S1") {
            ++scanner$successful_connections;
        } else {
            ++scanner$failed_connections;
        }
    }
    
    # Detecta serviços
    if (c?$service) {
        add scanner$services_detected[c$service];
    }
    
    # Análise de legitimidade
    scanner$is_likely_legitimate = analyze_legitimacy(scanner);
    
    # Atualiza target
    local target = targets[dest];
    add target$hosts[orig];
    add target$ports[dest_port];
    ++target$total_connections;
    target$last_seen = network_time();
    
    # DETECÇÃO 1: Port Scan Horizontal (muitas portas, poucos hosts)
    if (!scanner$is_likely_legitimate && |scanner$ports| >= port_scan_threshold && |scanner$hosts| <= 3) {
        local duration = scanner$last_seen - scanner$first_seen;
        local rate = |scanner$ports| / duration;
        
        local msg = SIMIR::format_portscan_message("HORIZONTAL_SCAN", 
            orig, fmt("Scanned %d ports on %d hosts in %s (rate: %.2f ports/sec)", 
            |scanner$ports|, |scanner$hosts|, duration_to_mins_secs(duration), rate));
        
        NOTICE([$note=Port_Scan_Detected,
                $msg=msg,
                $src=orig,
                $identifier=fmt("portscan_horizontal_%s", orig),
                $suppress_for=1hr]);
    }
    
    # DETECÇÃO 2: Port Scan Vertical (muitos hosts, poucas portas)  
    if (!scanner$is_likely_legitimate && |scanner$hosts| >= host_threshold && |scanner$ports| <= 5) {
        local msg = SIMIR::format_portscan_message("VERTICAL_SCAN",
            orig, fmt("Scanned %d hosts on %d ports", |scanner$hosts|, |scanner$ports|));
            
        NOTICE([$note=Port_Scan_Detected,
                $msg=msg,
                $src=orig,
                $identifier=fmt("portscan_vertical_%s", orig),
                $suppress_for=1hr]);
    }
    
    # DETECÇÃO 3: Stealth Scan (muitas conexões falhadas)
    if (scanner$failed_connections >= closed_port_threshold && scanner$successful_connections < 3) {
        local fail_rate = scanner$failed_connections / (scanner$total_connections * 1.0);
        
        if (fail_rate > 0.8) {
            local msg = SIMIR::format_portscan_message("STEALTH_SCAN",
                orig, fmt("High failure rate: %d failed / %d total connections (%.1f%%)", 
                scanner$failed_connections, scanner$total_connections, fail_rate * 100));
                
            NOTICE([$note=Stealth_Scan_Detected,
                    $msg=msg,
                    $src=orig,
                    $identifier=fmt("stealth_scan_%s", orig),
                    $suppress_for=1hr]);
        }
    }
    
    # DETECÇÃO 4: Host sendo muito escaneado
    if (|target$hosts| >= host_threshold) {
        local msg = fmt("[PORT-SCAN] [HIGH] Target: %s | Being scanned by %d different hosts", 
                       SIMIR::format_ip(dest), |target$hosts|);
                       
        NOTICE([$note=Port_Scan_Target,
                $msg=msg,
                $src=dest,
                $identifier=fmt("scan_target_%s", dest),
                $suppress_for=1hr]);
    }
}

# Inicialização
event zeek_init()
{
    print fmt("Port Scan Detector - Produção | Threshold: %d ports | Window: %s | Mode: %s", 
              port_scan_threshold, time_window, production_mode ? "PRODUCTION" : "DEBUG");
              
    if (production_mode) {
        print "Anti-false-positive filters: ENABLED";
        print fmt("Monitoring %d subnets for scan activity", |monitor_subnets|);
    }
}