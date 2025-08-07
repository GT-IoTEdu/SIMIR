# Script de teste para detecção de força bruta
# Testa diretamente as funções de detecção

@load base/frameworks/notice
@load ./brute-force-detector.zeek

event zeek_init()
{
    print "Iniciando teste do detector de força bruta...";
    
    # Simula detecção manual de força bruta SSH
    local ssh_attacker = 1.2.3.4;
    local ssh_target = 192.168.1.100;
    
    # Simula múltiplas tentativas SSH falhadas
    if (ssh_attacker !in BruteForce::brute_force_trackers) {
        BruteForce::brute_force_trackers[ssh_attacker] = [$service="SSH", $first_seen=network_time(), $last_seen=network_time()];
    }
    
    local ssh_tracker = BruteForce::brute_force_trackers[ssh_attacker];
    ssh_tracker$service = "SSH";
    ssh_tracker$failed_attempts = 6;  # Simula 6 tentativas falhadas
    ssh_tracker$consecutive_failures = 6;
    add ssh_tracker$targets[ssh_target];
    ssh_tracker$last_seen = network_time();
    
    # Gera notice manualmente para teste SSH
    NOTICE([$note=BruteForce::SSH_Brute_Force,
            $msg=fmt("Ataque de força bruta SSH detectado de %s: %d tentativas falhadas em %d hosts", 
                    ssh_attacker, ssh_tracker$failed_attempts, |ssh_tracker$targets|),
            $src=ssh_attacker,
            $identifier=cat(ssh_attacker, "ssh_brute")]);
    
    print "Teste de força bruta SSH executado - 6 tentativas falhadas";
    
    # Simula detecção manual de força bruta FTP
    local ftp_attacker = 5.6.7.8;
    local ftp_target = 192.168.1.200;
    
    if (ftp_attacker !in BruteForce::brute_force_trackers) {
        BruteForce::brute_force_trackers[ftp_attacker] = [$service="FTP", $first_seen=network_time(), $last_seen=network_time()];
    }
    
    local ftp_tracker = BruteForce::brute_force_trackers[ftp_attacker];
    ftp_tracker$service = "FTP";
    ftp_tracker$failed_attempts = 6;  # Simula 6 tentativas falhadas
    ftp_tracker$consecutive_failures = 6;
    add ftp_tracker$targets[ftp_target];
    ftp_tracker$last_seen = network_time();
    
    # Gera notice manualmente para teste FTP
    NOTICE([$note=BruteForce::FTP_Brute_Force,
            $msg=fmt("Ataque de força bruta FTP detectado de %s: %d tentativas falhadas em %d hosts", 
                    ftp_attacker, ftp_tracker$failed_attempts, |ftp_tracker$targets|),
            $src=ftp_attacker,
            $identifier=cat(ftp_attacker, "ftp_brute")]);
    
    print "Teste de força bruta FTP executado - 6 tentativas falhadas";
    
    # Simula detecção manual de força bruta HTTP
    local http_attacker = 9.10.11.12;
    local http_target = 192.168.1.50;
    
    if (http_attacker !in BruteForce::brute_force_trackers) {
        BruteForce::brute_force_trackers[http_attacker] = [$service="HTTP", $first_seen=network_time(), $last_seen=network_time()];
    }
    
    local http_tracker = BruteForce::brute_force_trackers[http_attacker];
    http_tracker$service = "HTTP";
    http_tracker$failed_attempts = 11;  # Simula 11 tentativas falhadas
    http_tracker$consecutive_failures = 11;
    add http_tracker$targets[http_target];
    http_tracker$last_seen = network_time();
    
    # Gera notice manualmente para teste HTTP
    NOTICE([$note=BruteForce::HTTP_Brute_Force,
            $msg=fmt("Ataque de força bruta HTTP detectado de %s: %d tentativas falhadas (401/403) em %d hosts", 
                    http_attacker, http_tracker$failed_attempts, |http_tracker$targets|),
            $src=http_attacker,
            $identifier=cat(http_attacker, "http_brute")]);
    
    print "Teste de força bruta HTTP executado - 11 tentativas falhadas";
    
    # Simula detecção manual de força bruta genérica (MySQL)
    local mysql_attacker = 3.4.5.6;
    local mysql_target = 192.168.1.60;
    
    if (mysql_attacker !in BruteForce::brute_force_trackers) {
        BruteForce::brute_force_trackers[mysql_attacker] = [$service="Generic", $first_seen=network_time(), $last_seen=network_time()];
    }
    
    local mysql_tracker = BruteForce::brute_force_trackers[mysql_attacker];
    mysql_tracker$service = "Generic";
    mysql_tracker$failed_attempts = 9;  # Simula 9 tentativas falhadas
    mysql_tracker$consecutive_failures = 9;
    add mysql_tracker$targets[mysql_target];
    mysql_tracker$last_seen = network_time();
    
    # Gera notice manualmente para teste genérico
    NOTICE([$note=BruteForce::Generic_Brute_Force,
            $msg=fmt("Possível ataque de força bruta detectado de %s: %d conexões falhadas para portas de autenticação em %d hosts", 
                    mysql_attacker, mysql_tracker$failed_attempts, |mysql_tracker$targets|),
            $src=mysql_attacker,
            $identifier=cat(mysql_attacker, "generic_brute")]);
    
    print "Teste de força bruta genérica (MySQL) executado - 9 tentativas falhadas";
    
    print "Todos os testes de força bruta foram executados!";
    print "Verifique o arquivo notice.log para ver os alertas gerados.";
}
