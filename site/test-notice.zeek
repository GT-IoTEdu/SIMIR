# Script de teste para verificar se notice funciona
@load base/frameworks/notice

module TestNotice;

export {
    redef enum Notice::Type += {
        Test_Notice
    };
}

# Flag para evitar múltiplos notices
global test_notice_sent = F;

# Gerar notice quando primeira conexão for detectada
event new_connection(c: connection)
{
    if (!test_notice_sent) {
        print "=== GERANDO NOTICE DE TESTE ===";
        
        NOTICE([$note=Test_Notice,
                $msg="Notice de teste gerado na primeira conexão",
                $src=c$id$orig_h,
                $dst=c$id$resp_h,
                $identifier="test_notice_connection"]);
        
        test_notice_sent = T;
        print "=== NOTICE DE TESTE ENVIADO ===";
    }
}
