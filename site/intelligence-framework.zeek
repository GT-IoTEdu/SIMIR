# Intelligence Framework para SIMIR - Versão Definitiva
# Compatível com Zeek 7.2.2 - Sem emojis e com sintaxe corrigida

@load base/frameworks/intel
@load base/frameworks/notice

export {
    redef enum Notice::Type += {
        Intelligence_Match,
        Malicious_IP_Hit,
        Malicious_Domain_Hit,
        Intel_Framework_Test
    };
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

# Debug de inicialização com notice de teste
event zeek_init()
{
    print "SIMIR Intelligence Framework INICIADO";
    print fmt("Total de feeds configurados: %d", |Intel::read_files|);
    
    # Gera notice de teste para verificar funcionamento
    NOTICE([$note=Intel_Framework_Test,
            $msg="SIMIR Intelligence Framework iniciado com sucesso",
            $identifier="intel_startup_test"]);
    
    print "Notice de teste gerado";
}

# Evento removido devido a incompatibilidade com Zeek 7.2.2

# Evento principal quando há match de intelligence
event Intel::match(s: Intel::Seen, items: set[Intel::Item])
{
    print fmt("=== INTELLIGENCE MATCH DETECTADO ===");
    print fmt("Indicador: %s", s$indicator);
    print fmt("Host: %s", s$host);
    print fmt("Onde visto: %s", s$where);
    
    for ( item in items ) {
        local notice_type = Intelligence_Match;
        local msg = "";
        
        # Determina tipo específico baseado no IOC
        switch ( item$indicator_type ) {
            case Intel::ADDR:
                notice_type = Malicious_IP_Hit;
                msg = fmt("IP MALICIOSO DETECTADO: %s (Fonte: %s)", s$indicator, item$meta$source);
                break;
                
            case Intel::DOMAIN:
                notice_type = Malicious_Domain_Hit;
                msg = fmt("DOMINIO MALICIOSO DETECTADO: %s (Fonte: %s)", s$indicator, item$meta$source);
                break;
                
            default:
                msg = fmt("AMEACA DETECTADA: %s (Tipo: %s, Fonte: %s)", 
                         s$indicator, item$indicator_type, item$meta$source);
                break;
        }
        
        print fmt("Gerando alerta: %s", msg);
        
        # Gera notice
        NOTICE([$note=notice_type,
                $msg=msg,
                $src=s$host,
                $identifier=fmt("intel_%s", s$indicator),
                $suppress_for=30sec]);
                
        print fmt("Alerta SIMIR gerado para indicador: %s", s$indicator);
    }
    
    print "=== FIM DO MATCH ===";
}