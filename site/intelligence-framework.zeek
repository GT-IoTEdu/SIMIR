# Intelligence Framework para SIMIR - Versão Final

@load base/frameworks/intel
@load base/frameworks/notice

export {
    redef enum Notice::Type += {
        Intelligence_Match,
        Malicious_IP_Hit,
        Malicious_Domain_Hit
    };
}

# Configurações do framework de inteligência - TODOS OS FEEDS
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

# Debug de inicialização
event zeek_init()
{
    print "🚀 SIMIR Intelligence Framework iniciado com sucesso!";
    print fmt("📊 Carregando feeds de: %s arquivos", |Intel::read_files|);
}

# Evento principal quando há match de intelligence
event Intel::match(s: Intel::Seen, items: set[Intel::Item])
{
    print fmt("�� INTELLIGENCE MATCH: Indicador %s detectado no host %s", s$indicator, s$host);
    
    for ( item in items ) {
        local notice_type = Intelligence_Match;
        local msg = "";
        
        # Determina tipo específico baseado no IOC
        switch ( item$indicator_type ) {
            case Intel::ADDR:
                notice_type = Malicious_IP_Hit;
                msg = fmt("🚨 IP MALICIOSO: %s (Fonte: %s)", s$indicator, item$meta$source);
                break;
                
            case Intel::DOMAIN:
                notice_type = Malicious_Domain_Hit;
                msg = fmt("🌐 DOMÍNIO MALICIOSO: %s (Fonte: %s)", s$indicator, item$meta$source);
                break;
                
            default:
                msg = fmt("⚠️ THREAT DETECTED: %s (Tipo: %s, Fonte: %s)", 
                         s$indicator, item$indicator_type, item$meta$source);
                break;
        }
        
        print fmt("📝 Gerando alerta: %s", msg);
        
        # Gera notice
        NOTICE([$note=notice_type,
                $msg=msg,
                $src=s$host,
                $identifier=cat("intel_", s$indicator),
                $suppress_for=60sec]);
                
        print fmt("✅ Alerta gerado para %s", s$indicator);
    }
}
