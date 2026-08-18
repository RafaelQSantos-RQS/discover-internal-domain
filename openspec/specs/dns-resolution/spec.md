# DNS Resolution Specification

## Purpose

Execução concorrente de consultas DNS sobre as combinações geradas, com worker pool, timeout por consulta e cancelamento, reportando subdomínios que resolvem.

## Requirements

### Requirement: Motor de consulta raw UDP
A ferramenta SHALL executar consultas DNS via pacotes UDP crus (estilo massdns), sem o stack completo de resolver (sem hosts file, sem cache interno, sem search domains). Respostas truncadas (bit TC) SHALL ser reconsultadas via TCP.

#### Scenario: Consulta via UDP
- **WHEN** a ferramenta consulta um FQDN
- **THEN** a consulta é enviada como pacote DNS cru via UDP ao resolver selecionado

#### Scenario: Resposta truncada
- **WHEN** a resposta UDP tem o bit TC setado
- **THEN** a consulta é repetida via TCP ao mesmo resolver

### Requirement: Worker pool adaptativo
A ferramenta SHALL executar consultas DNS com um número configurável de workers concorrentes, consumindo jobs de um canal com buffer limitado, e SHALL ajustar dinamicamente o número de workers ativos com base na latência das respostas.

#### Scenario: Múltiplos workers processando jobs
- **WHEN** a enumeração está em execução com N workers
- **THEN** até N consultas DNS são processadas simultaneamente

#### Scenario: Latência baixa
- **WHEN** as respostas chegam rapidamente (latência baixa)
- **THEN** o número de workers ativos aumenta até o limite configurado

#### Scenario: Latência alta
- **WHEN** as respostas demoram (latência alta)
- **THEN** o número de workers ativos diminui para evitar sobrecarga

### Requirement: Timeout e retry por consulta
Cada consulta DNS SHALL respeitar um timeout configurável com retry; consultas que excedem o timeout após as tentativas SHALL ser tratadas como não-resolvidas e não SHALL bloquear o worker.

#### Scenario: Consulta excede o timeout
- **WHEN** uma consulta DNS não responde dentro do timeout configurado após as tentativas
- **THEN** a consulta é descartada e o worker segue para o próximo job

### Requirement: Reporte de resultados com CNAME
A ferramenta SHALL reportar cada subdomínio que resolve para um ou mais endereços IP, com o FQDN completo, a lista de IPs e, quando presente, o alvo do CNAME, após aplicar filtragem de wildcard e cache negativo.

#### Scenario: Subdomínio resolve com CNAME
- **WHEN** um subdomínio resolve via CNAME para endereços IP que não são wildcard
- **THEN** o resultado (FQDN + IPs + alvo CNAME) é reportado para a camada de saída

#### Scenario: Subdomínio resolve sem CNAME
- **WHEN** um subdomínio resolve diretamente para endereços IP que não são wildcard
- **THEN** o resultado (FQDN + IPs) é reportado para a camada de saída

#### Scenario: Subdomínio não resolve
- **WHEN** um subdomínio não resolve (NXDOMAIN, timeout ou erro)
- **THEN** nenhum resultado é reportado para esse subdomínio

### Requirement: Pool de resolvers
A ferramenta SHALL consultar uma lista de resolvers DNS, distribuindo as consultas entre eles em round-robin. A lista SHALL vir do system config por default, ou de um arquivo informado via flag `-r`.

#### Scenario: Resolvers do sistema
- **WHEN** nenhuma flag `-r` é informada
- **THEN** os resolvers do system config são usados

#### Scenario: Resolvers customizados
- **WHEN** a flag `-r` informa um arquivo com resolvers
- **THEN** os resolvers do arquivo são usados

#### Scenario: Distribuição round-robin
- **WHEN** múltiplas consultas são executadas com múltiplos resolvers
- **THEN** as consultas são distribuídas entre os resolvers em round-robin

### Requirement: Cancelamento
A ferramenta SHALL interromper o processamento de jobs quando o contexto é cancelado (sinal de interrupção), encerrando os workers sem processar jobs restantes.

#### Scenario: Cancelamento durante execução
- **WHEN** o contexto é cancelado durante a enumeração
- **THEN** os workers param de processar novos jobs e a enumeração encerra