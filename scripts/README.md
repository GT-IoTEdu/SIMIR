# Scripts do Projeto SIMIR Zeek

Esta pasta contém todos os scripts utilizados no projeto SIMIR Zeek.

## Scripts Principais

### `entrypoint.sh`
Script principal de entrada do container Docker. Responsável por:
- Verificar a saúde do sistema
- Configurar permissões
- Verificar interface de rede
- Inicializar o Zeek
- Monitorar logs

### `check-interface.sh`
Script para verificação da interface de rede. Funcionalidades:
- Verifica se a interface existe
- Tenta ativar interface se estiver DOWN
- Testa captura de pacotes
- Mostra estatísticas da interface

**Uso:** `./check-interface.sh [nome_da_interface]`

### `setup-permissions.sh`
Script para configuração de permissões do sistema:
- Configura permissões dos diretórios do Zeek
- Usa setcap para permitir captura de rede sem root
- Ajusta ownership dos arquivos

### `test-container.sh`
Script para teste completo do container:
- Para container atual
- Faz rebuild da imagem
- Verifica interface de rede no host
- Inicia novo container
- Mostra logs iniciais

**Uso:** `./test-container.sh`

## Como usar

### Para testar o container:
```bash
# A partir da raiz do projeto
./run-test.sh

# Ou diretamente:
./scripts/test-container.sh
```

### Para verificar interface manualmente:
```bash
./scripts/check-interface.sh enx000ec89f6cc0
```

### Para acompanhar logs do container:
```bash
docker logs -f SIMIR_Z
```

## Estrutura de Logs

O entrypoint produz logs detalhados com prefixo `[Zeek Entrypoint]` para facilitar o debug.

## Troubleshooting

Se houver problemas:

1. **Container em loop de restart**: Verifique se a interface de rede existe no host
2. **Problemas de permissão**: Execute o container como privileged
3. **Interface não encontrada**: Use `ip link show` para listar interfaces disponíveis
4. **Zeek não inicia**: Verifique logs com `docker logs SIMIR_Z`
