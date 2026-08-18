# Generation Specification

## Purpose

Geração iterativa de combinações de subdomínios (a-z, 0-9, `-`) com limites de comprimento e quantidade, incluindo retomada a partir de checkpoint.

## Requirements

### Requirement: Alfabeto de combinações
O gerador SHALL produzir combinações usando apenas caracteres `a-z`, `0-9` e `-`, em ordem lexicográfica, para comprimentos de 1 até o comprimento máximo configurado.

#### Scenario: Geração de combinações de comprimento 1
- **WHEN** o comprimento máximo é 1
- **THEN** o gerador produz exatamente as 37 combinações de um caractere (`a` a `z`, `0` a `9`, `-`)

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
