# Generation Specification

## Purpose

Geração iterativa de combinações de subdomínios (a-z, 0-9, `-`) com limites de comprimento e quantidade, incluindo retomada a partir de checkpoint.

## Requirements

### Requirement: Geração exaustiva com comprimento mínimo
O gerador exaustivo SHALL produzir combinações usando apenas caracteres `a-z`, `0-9` e `-`, em ordem lexicográfica, para comprimentos do mínimo configurado até o comprimento máximo configurado. Quando nenhum mínimo é configurado, SHALL começar em comprimento 1. O total estimado SHALL refletir apenas os comprimentos cobertos.

#### Scenario: Geração de combinações de comprimento 1
- **WHEN** o comprimento máximo é 1
- **THEN** o gerador produz exatamente as 37 combinações de um caractere (`a` a `z`, `0` a `9`, `-`)

#### Scenario: Geração a partir de comprimento mínimo
- **WHEN** o comprimento mínimo é 3 e o máximo é 3
- **THEN** o gerador produz exatamente as 50653 combinações de três caracteres (`37³`)

#### Scenario: Comprimento mínimo não informado
- **WHEN** o usuário não informa comprimento mínimo
- **THEN** o gerador começa em comprimento 1

#### Scenario: Progressão para comprimento maior
- **WHEN** todas as combinações de um comprimento são esgotadas
- **THEN** o gerador avança para o próximo comprimento

### Requirement: Limite de comprimento máximo
O gerador SHALL limitar o comprimento máximo a 63 caracteres (limite de label DNS), mesmo que o usuário configure um valor maior.

#### Scenario: Comprimento máximo acima de 63
- **WHEN** o usuário configura comprimento máximo maior que 63
- **THEN** o gerador usa 63 como limite efetivo

### Requirement: Limite de combinações
O gerador SHALL parar de produzir combinações ao atingir o limite máximo de combinações configurado, quando este for maior que zero.

#### Scenario: Limite atingido
- **WHEN** o número de combinações produzidas atinge o limite configurado
- **THEN** o gerador para de produzir novas combinações

### Requirement: Retomada a partir de checkpoint
O gerador SHALL retomar a geração a partir do último índice e comprimento salvos no checkpoint, sem repetir combinações já processadas.

#### Scenario: Retomada após interrupção
- **WHEN** a enumeração é retomada com um checkpoint válido
- **THEN** o gerador continua da posição salva, produzindo apenas combinações ainda não processadas

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
