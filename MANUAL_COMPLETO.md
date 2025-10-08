# Manual Completo da Sonda SIMIR

## Índice
1. [Visão geral](#visão-geral)
2. [Conceitos básicos sobre o Zeek](#conceitos-básicos-sobre-o-zeek)
3. [Arquitetura da solução](#arquitetura-da-solução)
4. [Requisitos e instalação](#requisitos-e-instalação)
5. [Operação diária](#operação-diária)
6. [Detectores disponíveis](#detectores-disponíveis)
7. [Testes automatizados](#testes-automatizados)
8. [Logs e monitoramento](#logs-e-monitoramento)
9. [Solução de problemas](#solução-de-problemas)
10. [Referências e materiais](#referências-e-materiais)

---

## Visão geral
A SIMIR (Sonda Inteligente de Monitoramento Interno da Rede) é um conjunto de scripts e automações baseado na plataforma Zeek. A solução foi preparada para rodar em um container Docker em modo host, capturando o tráfego de rede diretamente da interface configurada e gerando alertas estruturados no arquivo `logs/notice.log`.

Principais objetivos:
- Observar tráfego de rede sem interferir no tráfego.
- Detectar comportamentos suspeitos, como port scans, tentativas de força bruta e ataques de negação de serviço.
- Correlacionar eventos com indicadores externos de ameaça.
- Fornecer um conjunto repetível de testes para validar o ambiente.

---

## Conceitos básicos sobre o Zeek
O Zeek é um analisador de tráfego em tempo real. Diferente de um firewall, ele opera de forma passiva, convertendo pacotes em eventos que podem ser processados por scripts. Cada protocolo conhecido pelo Zeek gera eventos específicos (HTTP, DNS, TLS, SSH, etc.). Os scripts instalados em `site/` definem o que fazer com cada evento.

Fluxo simplificado:
1. O container Zeek captura pacotes da interface definida pela variável `ZEEK_INTERFACE`.
2. O engine converte pacotes em eventos.
3. Os scripts disponíveis na pasta `site/` analisam os eventos e escrevem logs no diretório `logs/`.
4. Scripts auxiliares (como os de teste) interpretam os logs para validar o comportamento.

Para detalhes sobre protocolos e eventos disponíveis, consulte a documentação oficial do Zeek em <https://docs.zeek.org/>.

---

## Arquitetura da solução
```
┌────────────┐     ┌──────────────┐     ┌───────────────┐
│ Tráfego de │ --> │ Container    │ --> │ Logs e alerts │
│   rede     │     │ Zeek (SIMIR) │     │ notice/conn   │
└────────────┘     └──────────────┘     └───────────────┘
                         │                       │
                         │                       └──► Scripts de validação
                         └──► Scripts Zeek (site/)
```
Componentes principais:
- **Container Zeek**: executa o engine e carrega os scripts personalizados.
- **Scripts em `site/`**: implementam detectores, padrões de aviso e integração com feeds.
- **Scripts em `scripts/`**: fornecem automações (controle, testes, configuração de e-mail).
- **Logs em `logs/`**: armazenam a saída do Zeek para análise e auditoria.

---

## Requisitos e instalação

### Requisitos mínimos
- Sistema operacional Linux com suporte a Docker e Docker Compose.
- 2 vCPUs, 4 GB de memória RAM e 10 GB de espaço livre.
- Interface de rede com acesso ao tráfego que será monitorado.

### Dependências sugeridas
```bash
sudo apt update
sudo apt install -y docker.io docker-compose git python3
sudo systemctl enable docker
sudo systemctl start docker
```
Adicione o usuário ao grupo `docker` se desejar executar os comandos sem `sudo`:
```bash
sudo usermod -aG docker $USER
```
Efetue logout e login novamente para aplicar a mudança.

### Clonagem e configuração inicial
```bash
git clone <URL_DO_REPOSITORIO> simir
cd simir
```
Edite o arquivo `docker-compose.yml` e defina a interface de captura:
```yaml
environment:
  - ZEEK_INTERFACE=enp0s31f6   # substitua pela interface correta
```
### Inicialização
A forma mais rápida de subir o ambiente é executar:
```bash
./start-simir.sh
```
Esse script compila a imagem se necessário, aplica permissões e inicia o container.

Para controlar manualmente:
```bash
docker-compose build
./scripts/config-email.sh
docker-compose up -d
./scripts/simir-control.sh start
```

---

## Operação diária

### Ferramenta de controle
```bash
./scripts/simir-control.sh
```
A interface apresenta um menu com as principais operações:
- `configure`: configura parâmetros de e-mail.
- `start` / `stop`: inicia ou encerra serviços.
- `status`: mostra o estado atual.
- `simulate`: executa uma simulação de port scan.
- `logs`: mostra atalhos para os principais arquivos de log.

### Comandos diretos
```bash
./scripts/simir-control.sh start
./scripts/simir-control.sh stop
./scripts/simir-control.sh status
./scripts/test-complete.sh
```

### Monitoramento rápido
```bash
tail -f logs/notice.log
```

---

## Detectores disponíveis
Os detectores estão implementados em arquivos Zeek dentro da pasta `site/`. Todos emitem mensagens padronizadas por meio de `simir-notice-standards.zeek`.

### Port scan (`port-scan-detector.zeek`)
- Mantém estatísticas por origem, como quantidade de portas sondadas, hosts distintos e proporção de tentativas fracassadas.
- Diferencia varreduras horizontais (mesma porta em vários hosts) e verticais (muitas portas no mesmo host).
- Os limites podem ser ajustados com `redef` para as variáveis `port_scan_threshold`, `vertical_port_threshold`, `horizontal_host_threshold`, `failed_ratio_threshold` e `min_total_connections`.
- Emite notices do tipo `PortScan::Port_Scan`, `PortScan::Port_Scan_Target` e `PortScan::Closed_Port_Access`.

### Força bruta (`brute-force-detector.zeek`)
- Acompanha tentativas fracassadas de autenticação em SSH, FTP e HTTP.
- Considera tanto eventos específicos (respostas 401/403) quanto estados de conexão que indicam rejeição.
- Mensagens seguem o padrão `[BRUTE-FORCE]` e incluem serviço, atacante, alvo e quantidade de tentativas.

### DoS e DDoS (`ddos-detector.zeek`)
- Agrupa métricas por destino e por origem.
- Emite alertas quando o volume ultrapassa os limites definidos (`dos_threshold`, `ddos_total_threshold`, entre outros).
- As mensagens informam a quantidade de requisições e o número de fontes envolvidas.

### Framework de inteligência (`intelligence-framework.zeek`)
- Carrega feeds em `site/intel/` e inclui indicadores temporários de teste no arquivo `site/intel/test-auto.txt`.
- Correlaciona conexões com os feeds e gera notices que citam o indicador, o tipo (IP, domínio, URL) e a origem do dado.
- Há suporte para limpeza automática de indicadores via funções agendadas.

---

## Testes automatizados
O script `./scripts/test-complete.sh` executa uma bateria de validações:
1. Garante que o container esteja em execução e que os scripts Zeek compilam sem erros.
2. Injeta IOC conhecido (`1.1.1.1` e `example.com`) para validar o framework de inteligência.
3. Verifica se mensagens seguem o padrão definido.
4. Simula tráfego benigno para confirmar que o detector de port scan não gera falsos positivos excessivos.
5. Gera múltiplas respostas 401 para acionar o detector de força bruta.
6. Cria volume de conexões para disparar o detector de DoS/DDoS.
7. Confere a existência dos principais arquivos de log.

Cada etapa imprime no terminal se a checagem foi concluída com sucesso e quantos notices novos foram encontrados.

Além do teste completo, há scripts especializados na pasta `scripts/`:
- `test-brute-force.sh`: foca na detecção de força bruta.
- `test-intelligence.sh`: valida feeds e correlação.
- `test-port-scan.sh` (quando disponível na pasta `docs/`): apresenta comandos e dicas para simular scans reais.

---

## Logs e monitoramento
Os logs do Zeek ficam em `logs/`, montado como volume no container. Arquivos mais relevantes:
- `notice.log`: alertas e eventos de segurança (principal fonte para a operação).
- `conn.log`: lista de todas as conexões vistas.
- `dns.log`: consultas e respostas DNS.
- `http.log`: requisições HTTP.
- `ssl.log`: metadados de sessões TLS.
- `stdout.log` e `stderr.log`: saídas do serviço dentro do container.

Para visualizar os tipos de notices mais recentes:
```bash
cut -f 10 logs/notice.log | tail -n 20
```

Os logs são escritos no formato TSV (campos separados por tabulação). O cabeçalho explica a ordem das colunas.

---

## Solução de problemas

### O container não inicia
1. Verifique se a interface informada em `docker-compose.yml` existe (`ip addr show`).
2. Execute `sudo ./scripts/setup-permissions.sh` para ajustar permissões de captura.
3. Leia a saída com `docker logs -f SIMIR_Z` para identificar erros.

### Nenhum alerta está sendo gerado
1. Confirme se `logs/notice.log` está sendo atualizado (`tail -f logs/notice.log`).
2. Rode `./scripts/test-complete.sh` para acionar os detectores.
3. Certifique-se de que os feeds em `site/intel/` contêm indicadores válidos.

### Problemas com envio de e-mail
1. Gere uma senha de app e utilize `./scripts/config-email.sh`.
2. Teste com `./scripts/simir-control.sh test-email`.
3. Revise as variáveis de ambiente em `docker-compose.yml`.

### Ajuste de limites dos detectores
- Os arquivos Zeek possuem variáveis com `&redef`, permitindo alterar limites em um script adicional (`local.zeek` ou arquivo específico carregado depois). Exemplo:
  ```zeek
  redef PortScan::failed_ratio_threshold = 0.5;
  redef BruteForce::http_failed_threshold = 8;
  redef DDoS::dos_threshold = 30;
  ```
- Após alterar valores, reinicie o container (`docker-compose restart zeek`).

---

## Referências e materiais
- Documentação oficial do Zeek: <https://docs.zeek.org/>
- Guia rápido do projeto: arquivo `README.md` na raiz.
- Pasta `docs/`: reúne instruções complementares (montagem do ambiente, integração com outras ferramentas).
- Para contribuições, siga o padrão de mensagens em `simir-notice-standards.zeek` e execute `./scripts/test-complete.sh` antes de enviar mudanças.
