# Wildcard Detection Specification

## Purpose

Detecção de respostas DNS wildcard (domínio curinga) via probe de subdomínio aleatório e filtragem das respostas que correspondem ao padrão wildcard.

## Requirements

### Requirement: Detecção de wildcard
A ferramenta SHALL detectar wildcards consultando um subdomínio aleatório do domínio alvo; se o subdomínio aleatório resolver, os IPs retornados SHALL ser considerados o padrão wildcard.

#### Scenario: Wildcard presente
- **WHEN** um subdomínio aleatório do domínio alvo resolve para endereços IP
- **THEN** esses IPs são registrados como padrão wildcard

#### Scenario: Sem wildcard
- **WHEN** um subdomínio aleatório do domínio alvo não resolve
- **THEN** nenhum padrão wildcard é registrado

### Requirement: Filtragem de respostas wildcard
A ferramenta SHALL descartar resultados de subdomínios cujos IPs correspondam integralmente ao padrão wildcard detectado.

#### Scenario: Resposta totalmente wildcard
- **WHEN** todos os IPs de um subdomínio pertencem ao padrão wildcard
- **THEN** o subdomínio não é reportado como descoberta

#### Scenario: Resposta parcialmente wildcard
- **WHEN** pelo menos um IP de um subdomínio não pertence ao padrão wildcard
- **THEN** o subdomínio é reportado como descoberta com todos os seus IPs

### Requirement: Restauração de wildcard a partir de checkpoint
A ferramenta SHALL restaurar o padrão wildcard salvo no checkpoint, quando presente, sem necessidade de novo probe.

#### Scenario: Retomada com wildcard salvo
- **WHEN** a enumeração é retomada com um checkpoint que contém IPs wildcard
- **THEN** o padrão wildcard é restaurado do checkpoint e usado na filtragem

### Requirement: Desabilitação de detecção
A ferramenta SHALL permitir desabilitar a detecção e filtragem de wildcard via opção de linha de comando.

#### Scenario: Detecção desabilitada
- **WHEN** o usuário desabilita a detecção de wildcard
- **THEN** nenhum probe é realizado e nenhuma filtragem por wildcard é aplicada
