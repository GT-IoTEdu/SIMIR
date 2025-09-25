# Simple Intelligence Framework Test

@load base/frameworks/intel
@load base/frameworks/notice

# Configurações básicas
redef Intel::read_files += {
    "/usr/local/zeek/share/zeek/site/intel/malicious-ips.txt"
};

# Eventos para debug
event zeek_init()
{
    print "Intelligence Framework carregado";
}

event Intel::read_entry(desc: Intel::Desc, item: Intel::Item)
{
    print fmt("IOC carregado: %s tipo:%s fonte:%s", item$indicator, item$indicator_type, item$meta$source);
}

# Evento principal
event Intel::match(s: Intel::Seen, items: set[Intel::Item])
{
    print fmt("INTELLIGENCE MATCH: %s visto em %s", s$indicator, s$host);
    
    for ( item in items ) {
        print fmt("Detalhes: IOC=%s, Tipo=%s, Fonte=%s", 
                  item$indicator, item$indicator_type, item$meta$source);
        
        NOTICE([$note=Notice::Info,
                $msg=fmt("THREAT INTELLIGENCE MATCH: %s", s$indicator),
                $src=s$host,
                $identifier=cat(s$indicator)]);
    }
}
