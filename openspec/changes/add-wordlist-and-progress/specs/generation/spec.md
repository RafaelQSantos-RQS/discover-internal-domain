## MODIFIED Requirements

### Requirement: Geração exaustiva com comprimento mínimo
O gerador exaustivo SHALL produzir combinações usando apenas caracteres `a-z`, `0-9` e `-`, em ordem lexicográfica, para comprimentos do mínimo configurado até o comprimento máximo configurado. Quando nenhum mínimo é configurado, SHALL começar em comprimento 1. O total estimado SHALL refletir apenas os comprimentos cobertos.

#### Scenario: Geração a partir de comprimento mínimo
- **WHEN** o comprimento mínimo é 3 e o máximo é 3
- **THEN** o gerador produz exatamente as 50653 combinações de três caracteres (`37³`)

#### Scenario: Comprimento mínimo não informado
- **WHEN** o usuário não informa comprimento mínimo
- **THEN** o gerador começa em comprimento 1

### Requirement: Modo wordlist
O gerador SHALL suportar uma fonte alternativa de jobs a partir de um arquivo de wordlist: uma entrada por linha, ignorando linhas vazias e comentários iniciados por `#`. Cada linha é um subdomínio a testar, sem transformação. Ao retomar de checkpoint, SHALL continuar a partir do índice de linha salvo, sem repetir entradas.

#### Scenario: Wordlist carregada
- **WHEN** um arquivo de wordlist é informado
- **THEN** cada linha não vazia e não comentada do arquivo é um job a ser testado

#### Scenario: Comentários e linhas vazias ignorados
- **WHEN** o arquivo contém linhas vazias ou iniciadas por `#`
- **THEN** essas linhas não geram jobs

#### Scenario: Retomada de wordlist
- **WHEN** a enumeração é retomada a partir de um checkpoint em modo wordlist
- **THEN** a geração continua do índice de linha salvo, sem reprocessar entradas anteriores
