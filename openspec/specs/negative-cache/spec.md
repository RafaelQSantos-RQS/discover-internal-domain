# Negative Cache Specification

## Purpose

Cache de respostas DNS negativas (NXDOMAIN/timeout) para evitar consultas redundantes, com evicção LRU, limite de entradas e TTL configurável.

## Requirements

### Requirement: Cache de respostas negativas
A ferramenta SHALL armazenar em cache subdomínios que não resolveram (NXDOMAIN ou timeout), e SHALL pular a consulta DNS de subdomínios presentes no cache dentro do TTL.

#### Scenario: Consulta negativa repetida
- **WHEN** um subdomínio já cacheado como negativo é encontrado novamente dentro do TTL
- **THEN** a consulta DNS é pulada e nenhum resultado é reportado

#### Scenario: TTL expirado
- **WHEN** um subdomínio cacheado como negativo está com o TTL expirado
- **THEN** a consulta DNS é realizada novamente

### Requirement: Limite de entradas
O cache SHALL limitar o número de entradas a 100.000, evictando as entradas mais antigas em ordem de inserção (FIFO) quando o limite é atingido.

#### Scenario: Limite atingido
- **WHEN** o cache atinge 100.000 entradas e uma nova entrada é adicionada
- **THEN** a entrada adicionada primeiro é removida para acomodar a nova

### Requirement: TTL configurável
A ferramenta SHALL permitir configurar o TTL do cache via opção de linha de comando; TTL igual a zero SHALL desabilitar o cache.

#### Scenario: Cache desabilitado
- **WHEN** o usuário configura TTL zero
- **THEN** nenhuma resposta negativa é cacheada e todas as consultas são realizadas

### Requirement: Limpeza de entradas expiradas
A ferramenta SHALL remover periodicamente entradas expiradas do cache para evitar crescimento desnecessário.

#### Scenario: Limpeza periódica
- **WHEN** a limpeza periódica é executada
- **THEN** entradas com TTL expirado são removidas do cache
