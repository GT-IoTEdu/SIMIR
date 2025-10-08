# SIMIR - Sonda Inteligente de Monitoramento Interno da Rede

## Apresentação
A SIMIR é uma sonda de monitoramento baseada no Zeek projetada para redes internas. O repositório reúne sensores, scripts de detecção e automações de testes que ajudam a validar o ambiente periodicamente. Os alertas são emitidos no arquivo `logs/notice.log`, que segue um padrão unificado definido pelos scripts da pasta `site/`.

## Início rápido
```bash
./start-simir.sh
```
O comando acima configura o container, aplica permissões necessárias e inicia todos os serviços.

## Recursos principais
- Detecção de port scan com correlação vertical e horizontal e cálculo da taxa de falhas das conexões.
- Detector de força bruta para SSH, FTP e HTTP com mensagens padronizadas.
- Detector de DoS e DDoS para tráfego volumétrico, com limites ajustáveis.
- Framework de inteligência que consome feeds externos (`site/intel/`) e valida indicadores automaticamente.
- Scripts de teste (`./scripts/test-complete.sh`) que verificam carregamento do Zeek, funcionamento dos detectores e formato dos avisos.
- Interface interativa (`./scripts/simir-control.sh`) para configurar alertas por e-mail, iniciar e acompanhar o sensor.

## Estrutura do repositório
```
├── docker-compose.yml       # Orquestra o container Zeek em modo host
├── Dockerfile               # Imagem base da sonda
├── start-simir.sh           # Inicialização automatizada
├── dev.sh                   # Ações usuais de desenvolvimento
├── scripts/                 # Scripts de operação, testes e utilitários
│   ├── simir-control.sh     # Interface interativa de gerenciamento
│   ├── test-complete.sh     # Testes integrados das detecções
│   └── ...
├── site/                    # Scripts Zeek personalizados
│   ├── local.zeek
│   ├── intelligence-framework.zeek
│   ├── port-scan-detector.zeek
│   ├── brute-force-detector.zeek
│   ├── ddos-detector.zeek
│   └── simir-notice-standards.zeek
├── logs/                    # Logs compartilhados com o container
└── docs/                    # Documentação complementar
```

## Operações básicas
```bash
# Interface principal com menu e atalhos
./scripts/simir-control.sh

# Inicializar ou parar serviços de forma direta
./scripts/simir-control.sh start
./scripts/simir-control.sh stop
./scripts/simir-control.sh status

# Executar a suíte de testes
./scripts/test-complete.sh

# Simular um port scan controlado
./scripts/simir-control.sh simulate
```

## Configuração de alertas por e-mail
1. Ative a verificação em duas etapas na conta fornecedora de e-mail (ex.: Gmail).
2. Gere uma senha de aplicativo específica para o SIMIR.
3. Execute o assistente:
   ```bash
   ./scripts/config-email.sh
   ```
4. Valide o envio:
   ```bash
   ./scripts/simir-control.sh test-email
   ```
As variáveis `SIMIR_SENDER_EMAIL`, `SIMIR_EMAIL_PASSWORD` e `SIMIR_RECIPIENT_EMAIL` podem ser definidas em `docker-compose.yml` para automatizar o processo.

## Logs importantes
- `logs/notice.log`: alertas de port scan, força bruta, DDoS e inteligência.
- `logs/conn.log`, `logs/dns.log`, `logs/http.log`: metadados de conexões coletados pelo Zeek.
- `logs/stdout.log` e `logs/stderr.log`: saída dos serviços dentro do container.

Para acompanhamento contínuo:
```bash
tail -f logs/notice.log
```

## Solução de problemas
- Confirme o estado do container com `docker ps` e `docker logs -f SIMIR_Z`.
- Verifique a interface de captura definida em `docker-compose.yml` (`ZEEK_INTERFACE`).
- Quando alertas não forem gerados, execute `./scripts/test-complete.sh` e revise `logs/notice.log`.
- Para permissões de captura, utilize `sudo ./scripts/setup-permissions.sh`.

## Documentação complementar
O arquivo `MANUAL_COMPLETO.md` detalha detectores, fluxos de logs e procedimentos avançados. A pasta `docs/` reúne passos adicionais de integração e referência.
