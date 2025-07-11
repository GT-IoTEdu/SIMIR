# Script Zeek para detecção de port scan
# Detecta tentativas de port scan e gera alertas

@load base/frameworks/notice
@load base/protocols/conn

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

    # Configurações
    global port_scan_threshold = 10;  # Número de portas diferentes para considerar port scan
    global time_window = 5min;        # Janela de tempo para análise
    global closed_port_threshold = 5;  # Tentativas em portas fechadas
}

# Estrutura para rastrear tentativas de conexão
type scan_tracker: record {
    hosts: set[addr] &default=set();
    ports: set[port] &default=set();
    connections: count &default=0;
    first_seen: time;
    last_seen: time;
};

# Tabelas para rastrear atividade
global scanners: table[addr] of scan_tracker &create_expire=time_window;
global targets: table[addr] of scan_tracker &create_expire=time_window;

# Função para detectar port scan baseado em conexões
event connection_state_remove(c: connection)
{
    local orig = c$id$orig_h;
    local dest = c$id$resp_h;
    local dest_port = c$id$resp_p;
    
    # Ignora tráfego local (mesmo host)
    if (orig == dest)
        return;
    
    # Ignora endereços privados fazendo conexões para a internet
    if (Site::is_private_addr(orig) && !Site::is_private_addr(dest))
        return;
    
    # Inicializa tracker para scanner se não existir
    if (orig !in scanners) {
        scanners[orig] = [$first_seen=network_time(), $last_seen=network_time()];
    }
    
    # Inicializa tracker para target se não existir
    if (dest !in targets) {
        targets[dest] = [$first_seen=network_time(), $last_seen=network_time()];
    }
    
    # Atualiza informações do scanner
    local scanner = scanners[orig];
    add scanner$hosts[dest];
    add scanner$ports[dest_port];
    ++scanner$connections;
    scanner$last_seen = network_time();
    
    # Atualiza informações do target
    local target = targets[dest];
    add target$hosts[orig];
    add target$ports[dest_port];
    ++target$connections;
    target$last_seen = network_time();
    
    # Verifica se conexão foi rejeitada ou falhou
    local connection_failed = F;
    if (c?$conn && c$conn?$conn_state) {
        if (c$conn$conn_state in set("REJ", "S0", "OTH")) {
            connection_failed = T;
        }
    }
    
    # Detecta port scan por número de portas diferentes
    if (|scanner$ports| >= port_scan_threshold) {
        NOTICE([$note=Port_Scan,
                $msg=fmt("Port scan detectado de %s para %d hosts, %d portas diferentes em %s", 
                        orig, |scanner$hosts|, |scanner$ports|, 
                        duration_to_mins_secs(scanner$last_seen - scanner$first_seen)),
                $src=orig,
                $identifier=cat(orig)]);
    }
    
    # Detecta tentativas em portas fechadas
    if (connection_failed && scanner$connections >= closed_port_threshold) {
        NOTICE([$note=Closed_Port_Access,
                $msg=fmt("Múltiplas tentativas em portas fechadas de %s (%d tentativas)", 
                        orig, scanner$connections),
                $src=orig,
                $identifier=cat(orig, "closed_ports")]);
    }
    
    # Detecta host sendo muito escaneado
    if (|target$hosts| >= port_scan_threshold) {
        NOTICE([$note=Port_Scan_Target,
                $msg=fmt("Host %s está sendo escaneado por %d hosts diferentes", 
                        dest, |target$hosts|),
                $src=dest,
                $identifier=cat(dest, "target")]);
    }
}

# Event para limpar dados antigos
event zeek_init()
{
    print fmt("Port Scan Detection ativo - Threshold: %d portas, Janela: %s", 
              port_scan_threshold, time_window);
}
