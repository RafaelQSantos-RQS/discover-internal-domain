## Purpose

Interface de linha de comando da ferramenta de enumeração DNS por brute-force, responsável por receber e validar opções, exibir resultados e encerrar graciosamente.

## ADDED Requirements

### Requirement: Opções de linha de comando
A ferramenta SHALL aceitar as seguintes opções via linha de comando: domínio base (obrigatório), comprimento máximo de subdomínio, número de workers, timeout por consulta DNS, habilitação de detecção de wildcard, arquivo de saída, limite máximo de combinações, tamanho do buffer de jobs, arquivo de checkpoint e TTL do cache negativo.

#### Scenario: Execução com opções válidas
- **WHEN** o usuário executa a ferramenta com domínio e opções válidas
- **THEN** a enumeração inicia com as opções fornecidas

#### Scenario: Domínio ausente
- **WHEN** o usuário executa a ferramenta sem informar o domínio
- **THEN** a ferramenta exibe erro e encerra com código de saída não-zero

### Requirement: Validação de opções
A ferramenta SHALL validar as opções antes de iniciar a enumeração: comprimento máximo entre 1 e 63 (limite de label DNS), número de workers maior ou igual a 1, buffer maior ou igual a 1 e TTL de cache não-negativo. Valores inválidos SHALL resultar em erro com mensagem clara e código de saída não-zero.

#### Scenario: Comprimento máximo acima do limite
- **WHEN** o usuário informa comprimento máximo maior que 63
- **THEN** a ferramenta limita o valor a 63 e continua

#### Scenario: Workers inválidos
- **WHEN** o usuário informa workers menor que 1
- **THEN** a ferramenta exibe erro e encerra com código de saída não-zero

### Requirement: Saída de resultados
A ferramenta SHALL exibir cada subdomínio descoberto no formato `fqdn -> ip1,ip2` (IPs separados por vírgula) em stdout, e SHALL exibir um resumo final (total verificado, total encontrado, tempo decorrido) em stderr.

#### Scenario: Subdomínio descoberto
- **WHEN** um subdomínio resolve para um ou mais endereços IP
- **THEN** a ferramenta imprime `fqdn -> ip1,ip2` em stdout

#### Scenario: Fim da enumeração
- **WHEN** a enumeração termina normalmente
- **THEN** a ferramenta imprime o resumo final em stderr

### Requirement: Encerramento gracioso
A ferramenta SHALL encerrar graciosamente ao receber SIGINT ou SIGTERM, salvando o checkpoint final (se configurado) antes de sair.

#### Scenario: Interrupção por sinal
- **WHEN** o usuário envia SIGINT ou SIGTERM durante a enumeração
- **THEN** a ferramenta interrompe o trabalho, salva o checkpoint final se configurado e encerra sem erro

### Requirement: Ajuda
A ferramenta SHALL exibir ajuda com todas as opções e descrições ao receber `--help`.

#### Scenario: Solicitação de ajuda
- **WHEN** o usuário executa a ferramenta com `--help`
- **THEN** a ferramenta exibe a lista de opções e encerra com código de saída zero