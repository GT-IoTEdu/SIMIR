# Intelligence Framework para SIMIR - Versão Produção
# Compatível com Zeek 7.2.2 - Otimizado para ambiente produtivo
# Sistema robusto de detecção de ameaças baseado em Intelligence

@load base/frameworks/intel
@load base/frameworks/notice
@load ./simir-notice-standards.zeek

# Verificação de compatibilidade com versão do Zeek
@if (Version::info$version_number < 70200)
    @error "Este script requer Zeek 7.2.0 ou superior"
@endif

export {
    redef enum Notice::Type += {
        Intelligence_Match,
        Malicious_IP_Hit,
        Malicious_Domain_Hit,
        Malicious_URL_Hit,
        Intel_Framework_Test,
        Intel_Framework_Ready,
        Intel_Feed_Error
    };
    
    # Configurações de produção
    global production_mode: bool = T &redef;
    global min_confidence_level: string = "MEDIUM" &redef;
    global enable_geo_context: bool = T &redef;
    
    # Estatísticas do framework
    global intel_stats: table[string] of count &default=0;
}

# Configurações do framework de inteligência
redef Intel::read_files += {
    "/usr/local/zeek/share/zeek/site/intel/test-simple.txt",
    "/usr/local/zeek/share/zeek/site/intel/malicious-ips.txt",
    "/usr/local/zeek/share/zeek/site/intel/malicious-domains.txt",
    "/usr/local/zeek/share/zeek/site/intel/feodo-ips.txt",
    "/usr/local/zeek/share/zeek/site/intel/hostfile-domains.txt",
    "/usr/local/zeek/share/zeek/site/intel/spamhaus-drop.txt",
    "/usr/local/zeek/share/zeek/site/intel/tor-exits.txt",
    "/usr/local/zeek/share/zeek/site/intel/urlhaus-domains.txt",
    "/usr/local/zeek/share/zeek/site/intel/suricata-malware.txt"
};

# Inicialização do framework de produção
event zeek_init()
{
    print "SIMIR Intelligence Framework - Modo Produção INICIADO";
    print fmt("Feeds de intelligence configurados: %d", |Intel::read_files|);
    
    # Validação de feeds em modo produção
    local valid_feeds = 0;
    for (feed in Intel::read_files) {
        if (production_mode) {
            # Em produção, apenas lista feeds sem detalhes sensíveis
            print fmt("Feed ativo: [REDACTED]");
        } else {
            print fmt("Feed configurado: %s", feed);
        }
        ++valid_feeds;
    }
    
    # Inicializa estatísticas
    intel_stats["feeds_loaded"] = valid_feeds;
    intel_stats["matches_detected"] = 0;
    intel_stats["high_confidence_matches"] = 0;
    
    # Notice padronizado de inicialização
    NOTICE([$note=Intel_Framework_Ready,
            $msg="[SYSTEM] [INFO] SIMIR Intelligence Framework pronto para produção",
            $identifier="intel_production_ready"]);
    
    print fmt("Framework pronto - %d feeds ativos", valid_feeds);
}

# Evento removido - Intel::item_inserted não existe no Zeek 7.2.2

# Evento removido devido a incompatibilidade com Zeek 7.2.2

# Evento principal quando há match de intelligence - Versão Produção
event Intel::match(s: Intel::Seen, items: set[Intel::Item])
{
    # Incrementa estatísticas
    ++intel_stats["matches_detected"];
    
    if (!production_mode) {
        print fmt("=== INTELLIGENCE MATCH DETECTADO ===");
        print fmt("Indicador: %s", s$indicator);
        print fmt("Host: %s", s$host);
        print fmt("Contexto: %s", s$where);
    }
    
    local matches_processados = 0;
    
    for ( item in items ) {
        ++matches_processados;
        local notice_type = Intelligence_Match;
        local confidence = item$meta?$desc ? item$meta$desc : "MEDIUM";
        local source = item$meta$source;
        
        # Filtra matches por nível de confiança se configurado
        if (min_confidence_level == "HIGH" && confidence != "HIGH" && confidence != "CRITICAL") {
            continue;
        }
        
        # Determina tipo específico e gera mensagem padronizada
        switch ( item$indicator_type ) {
            case Intel::ADDR:
                notice_type = Malicious_IP_Hit;
                local msg_ip = SIMIR::format_intel_message(s$indicator, "IP", source, confidence);
                
                # Contexto adicional para IPs
                if (enable_geo_context && s?$host) {
                    msg_ip += fmt(" | Connection from: %s", SIMIR::format_ip(s$host));
                }
                
                NOTICE([$note=notice_type,
                        $msg=msg_ip,
                        $src=s$host,
                        $identifier=fmt("intel_ip_%s", s$indicator),
                        $suppress_for=300sec]);
                break;
                
            case Intel::DOMAIN:
                notice_type = Malicious_Domain_Hit;
                local msg_domain = SIMIR::format_intel_message(s$indicator, "DOMAIN", source, confidence);
                
                if (s?$host) {
                    msg_domain += fmt(" | Queried by: %s", SIMIR::format_ip(s$host));
                }
                
                NOTICE([$note=notice_type,
                        $msg=msg_domain,
                        $src=s$host,
                        $identifier=fmt("intel_domain_%s", s$indicator),
                        $suppress_for=300sec]);
                break;
                
            case Intel::URL:
                notice_type = Malicious_URL_Hit;
                local msg_url = SIMIR::format_intel_message(s$indicator, "URL", source, confidence);
                
                NOTICE([$note=notice_type,
                        $msg=msg_url,
                        $src=s$host,
                        $identifier=fmt("intel_url_%s", md5_hash(s$indicator)),
                        $suppress_for=300sec]);
                break;
                
            default:
                local msg_generic = SIMIR::format_intel_message(s$indicator, fmt("%s", item$indicator_type), source, confidence);
                
                NOTICE([$note=Intelligence_Match,
                        $msg=msg_generic,
                        $src=s$host,
                        $identifier=fmt("intel_generic_%s", md5_hash(s$indicator)),
                        $suppress_for=300sec]);
                break;
        }
        
        # Incrementa contador de matches de alta confiança
        if (confidence == "HIGH" || confidence == "CRITICAL") {
            ++intel_stats["high_confidence_matches"];
        }
    }
    
    if (!production_mode) {
        print fmt("=== MATCH PROCESSADO - %d alertas gerados ===", matches_processados);
    }
}

# Evento para relatório de estatísticas (executado periodicamente)
event generate_intel_stats()
{
    if (!production_mode) {
        print fmt("=== ESTATÍSTICAS INTELLIGENCE ===");
        print fmt("Feeds ativos: %d", intel_stats["feeds_loaded"]);
        print fmt("Matches detectados: %d", intel_stats["matches_detected"]);
        print fmt("Matches alta confiança: %d", intel_stats["high_confidence_matches"]);
    }
    
    # Reagenda para próxima execução
    schedule 1hr { generate_intel_stats() };
}

# Agenda primeiro relatório
event zeek_init() &priority=-5
{
    schedule 1hr { generate_intel_stats() };
}