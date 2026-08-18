# DNS Resolution Specification

## Purpose

Execução concorrente de consultas DNS sobre as combinações geradas, com worker pool, timeout por consulta e cancelamento, reportando subdomínios que resolvem.

## Requirements

### Requirement: Worker pool concorrente
A ferramenta SHALL executar consultas DNS com um número configurável de workers concorrentes, consumindo jobs de um canal com buffer limitado.

#### Scenario: Múltiplos workers processando jobs
- **WHEN** a enumeração está em execução com N workers
- **THEN** até N consultas DNS são processadas simultaneamente

### Requirement: Timeout por consulta
Cada consulta DNS SHALL respeitar um timeout configurável; consultas que excedem o timeout SHALL ser tratadas como não-resolvidas e não SHALL bloquear o worker.

#### Scenario: Consulta excede o timeout
- **WHEN** uma consulta DNS não responde dentro do timeout configurado
- **THEN** a consulta é descartada e o worker segue para o próximo job

### Requirement: Reporte de resultados
A ferramenta SHALL reportar cada subdomínio que resolve para um ou mais endereços IP, com o FQDN completo e a lista de IPs, após aplicar filtragem de wildcard e cache negativo.

#### Scenario: Subdomínio resolve
- **WHEN** um subdomínio resolve para endereços IP que não são wildcard
- **THEN** o resultado (FQDN + IPs) é reportado para a camada de saída

#### Scenario: Subdomínio não resolve
- **WHEN** um subdomínio não resolve (NXDOMAIN, timeout ou erro)
- **THEN** nenhum resultado é reportado para esse subdomínio

### Requirement: Cancelamento
A ferramenta SHALL interromper o processamento de jobs quando o contexto é cancelado (sinal de interrupção), encerrando os workers sem processar jobs restantes.

#### Scenario: Cancelamento durante execução
- **WHEN** o contexto é cancelado durante a enumeração
- **THEN** os workers param de processar novos jobs e a enumeração encerra
