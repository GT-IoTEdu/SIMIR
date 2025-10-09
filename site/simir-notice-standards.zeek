# SIMIR - Padrões de Mensagens para Notice.log
# Definições padronizadas para logs de produção

@load base/frameworks/notice

module SIMIR;

export {
    # Função para formatação padronizada de timestamps
    global format_timestamp: function(ts: time): string;
    
    # Função para padronização de IPs
    global format_ip: function(ip: addr): string;
    
    # Função para formatação de mensagens de intelligence
    global format_intel_message: function(indicator: string, itype: string, source: string, confidence: string &default="MEDIUM"): string;
    
    # Função para formatação de mensagens de port scan
    global format_portscan_message: function(action: string, src: addr, details: string): string;
    
    # Função para formatação de mensagens de brute force
    global format_bruteforce_message: function(service: string, src: addr, target: addr, attempts: count): string;

    # Função para formatação de mensagens de DDoS/DoS
    global format_ddos_message: function(target: addr, service_port: port, attempts: count, unique_sources: count, attack_type: string): string;
    
    # Níveis de severidade padronizados
    type Severity: enum { LOW, MEDIUM, HIGH, CRITICAL };
    
    # Estrutura padronizada para metadados de notice
    type NoticeMetadata: record {
        severity: Severity;
        category: string;
        subcategory: string;
        confidence: string &default="MEDIUM";
        action_required: bool &default=F;
    };
}

# Implementação das funções de formatação
function format_timestamp(ts: time): string
{
    return strftime("%Y-%m-%d %H:%M:%S UTC", ts);
}

function format_ip(ip: addr): string
{
    # Mascarar IPs privados para logs de produção se necessário
    local ip_str = fmt("%s", ip);
    
    # Identificar tipo de IP
    if (Site::is_private_addr(ip)) {
        return fmt("[PRIVATE] %s", ip_str);
    } else {
        return fmt("[PUBLIC] %s", ip_str);
    }
}

function format_intel_message(indicator: string, itype: string, source: string, confidence: string &default="MEDIUM"): string
{
    # Formato: Threat detected: <indicator> | Type: <type> | Source: <source> | Severity: HIGH
    return fmt("Threat detected: %s | Type: %s | Source: %s | Severity: HIGH", 
               indicator, itype, source);
}

function format_portscan_message(action: string, src: addr, details: string): string
{
    local severity = "MEDIUM";
    local pattern_label = action;

    switch (action) {
        case "MULTIPLE_HOSTS":
            severity = "HIGH";
            pattern_label = "MULTIPLE_HOSTS";
            break;
        case "WIDE_SCAN":
            severity = "HIGH";
            pattern_label = "WIDE";
            break;
        case "VERTICAL":
            severity = "HIGH";
            pattern_label = "VERTICAL";
            break;
        case "HORIZONTAL":
            severity = "HIGH";
            pattern_label = "HORIZONTAL";
            break;
        case "TARGETED":
            severity = "HIGH";
            pattern_label = "TARGET";
            break;
        case "FAILED_PROBING":
            severity = "MEDIUM";
            pattern_label = "FAILED";
            break;
        default:
            pattern_label = action;
            break;
    }

    # Formato: Port scan detected | Attacker: <ip> | Pattern: <type> | Details: <info> | Severity: <level>
    return fmt("Port scan detected | Attacker: %s | Pattern: %s | %s | Severity: %s",
               format_ip(src), pattern_label, details, severity);
}

function format_bruteforce_message(service: string, src: addr, target: addr, attempts: count): string
{
    local severity = "HIGH";
    if (attempts >= 20)
        severity = "CRITICAL";
    
    # Formato: Brute force attack detected | Service: <service> | Attacker: <ip> | Target: <ip> | Attempts: <count> | Severity: <level>
    return fmt("Brute force attack detected | Service: %s | Attacker: %s | Target: %s | Attempts: %d | Severity: %s", 
               service, format_ip(src), format_ip(target), attempts, severity);
}

function format_ddos_message(target: addr, service_port: port, attempts: count, unique_sources: count, attack_type: string): string
{
    local severity = "HIGH";
    if (attempts >= 200 || unique_sources >= 25)
        severity = "CRITICAL";
    
    # Formato: DDoS attack detected | Target: <ip:port> | Type: <type> | Requests: <count> | Sources: <count> | Severity: <level>
    return fmt("DDoS attack detected | Target: %s:%s | Type: %s | Requests: %d | Sources: %d | Severity: %s",
               format_ip(target), port_to_count(service_port), attack_type, attempts, unique_sources, severity);
}