## MODIFIED Requirements

### Requirement: Opções de linha de comando
A ferramenta SHALL aceitar as seguintes opções via linha de comando: domínio base (obrigatório), comprimento máximo de subdomínio, comprimento mínimo de subdomínio, número de workers, timeout por consulta DNS, habilitação de detecção de wildcard, arquivo de saída, limite máximo de combinações, tamanho do buffer de jobs, arquivo de checkpoint, TTL do cache negativo, arquivo de resolvers customizados, arquivo de wordlist e inclusão do domínio raiz.

#### Scenario: Execução com opções válidas
- **WHEN** o usuário executa a ferramenta com domínio e opções válidas
- **THEN** a enumeração inicia com as opções fornecidas

#### Scenario: Domínio ausente
- **WHEN** o usuário executa a ferramenta sem informar o domínio
- **THEN** a ferramenta exibe erro e encerra com código de saída não-zero

### Requirement: Validação de opções
A ferramenta SHALL validar as opções antes de iniciar a enumeração: comprimento máximo entre 1 e 63 (limite de label DNS), comprimento mínimo entre 1 e o comprimento máximo, número de workers maior ou igual a 1, buffer maior ou igual a 1, TTL de cache não-negativo, arquivo de resolvers legível com pelo menos um resolver válido e arquivo de wordlist legível com pelo menos uma entrada. Valores inválidos SHALL resultar em erro com mensagem clara e código de saída não-zero.

#### Scenario: Comprimento máximo acima do limite
- **WHEN** o usuário informa comprimento máximo maior que 63
- **THEN** a ferramenta limita o valor a 63 e continua

#### Scenario: Comprimento mínimo acima do máximo
- **WHEN** o usuário informa comprimento mínimo maior que o comprimento máximo
- **THEN** a ferramenta exibe erro e encerra com código de saída não-zero

#### Scenario: Workers inválidos
- **WHEN** o usuário informa workers menor que 1
- **THEN** a ferramenta exibe erro e encerra com código de saída não-zero

#### Scenario: Arquivo de resolvers inválido
- **WHEN** o usuário informa um arquivo de resolvers inexistente, ilegível ou sem resolvers válidos
- **THEN** a ferramenta exibe erro e encerra com código de saída não-zero

#### Scenario: Arquivo de wordlist inválido
- **WHEN** o usuário informa um arquivo de wordlist inexistente, ilegível ou sem entradas
- **THEN** a ferramenta exibe erro e encerra com código de saída não-zero

### Requirement: Progresso ao vivo
A ferramenta SHALL exibir progresso da enumeração em stderr, atualizado a cada segundo: tempo decorrido, total verificado, percentual do total estimado, taxa de consultas por segundo e contagem de subdomínios encontrados.

#### Scenario: Progresso durante a enumeração
- **WHEN** a enumeração está em execução
- **THEN** a ferramenta atualiza a linha de progresso em stderr a cada segundo com as métricas atuais

#### Scenario: Fim da enumeração
- **WHEN** a enumeração termina
- **THEN** a linha de progresso é encerrada antes do resumo final
