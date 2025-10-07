# Intelligence Framework Simples para Debug
@load base/frameworks/intel
@load base/frameworks/notice

export {
    redef enum Notice::Type += {
        Intel_Test_Match
    };
}

# Configuração simples dos feeds
redef Intel::read_files += {
    "/usr/local/zeek/share/zeek/site/intel/test-simple.txt",
    "/usr/local/zeek/share/zeek/site/intel/test-detection.txt"
};

event zeek_init()
{
    print fmt("INTEL DEBUG: Carregando %d feeds", |Intel::read_files|);
    for (f in Intel::read_files) {
        print fmt("INTEL DEBUG: Feed: %s", f);
    }
}

event Intel::match(s: Intel::Seen, items: set[Intel::Item])
{
    print fmt("INTEL MATCH ENCONTRADO! IP: %s", s$indicator);
    
    NOTICE([$note=Intel_Test_Match,
            $msg=fmt("TESTE: IP suspeito detectado: %s", s$indicator)]);
}