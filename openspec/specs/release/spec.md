# Release Specification

## Purpose

Publicação de binários compilados do dnsbrute (Linux, macOS e Windows) como GitHub Release em tags versionadas.

## Requirements

### Requirement: Gatilho de execução
O workflow de release SHALL executar quando uma tag com prefixo `v` seguida de versão (ex.: `v1.0.0`) é criada.

#### Scenario: Tag versionada criada
- **WHEN** uma tag `v*.*.*` é criada
- **THEN** o workflow de release é executado

#### Scenario: Tag não versionada
- **WHEN** uma tag sem o formato `v*.*.*` é criada
- **THEN** o workflow de release não é executado

### Requirement: Compilação multiplataforma
O workflow SHALL compilar o binário para Linux, macOS e Windows, nas arquiteturas amd64 e arm64, com otimizações de release.

#### Scenario: Compilação de todos os alvos
- **WHEN** o workflow de release é executado
- **THEN** binários são compilados para Linux, macOS e Windows (amd64 e arm64)

### Requirement: Publicação de release
O workflow SHALL criar um GitHub Release para a tag e anexar todos os binários compilados como assets, com nomes que identifiquem sistema operacional e arquitetura.

#### Scenario: Release criado com assets
- **WHEN** a compilação de todos os alvos termina com sucesso
- **THEN** um GitHub Release é criado com os binários anexados (ex.: `dnsbrute-linux-amd64`, `dnsbrute-windows-amd64.exe`)

### Requirement: Falha interrompe o release
O workflow SHALL criar o GitHub Release para a tag antes de anexar os assets e SHALL falhar se qualquer alvo não compilar. Como o release é criado antes do upload, uma falha de alvo SHALL resultar em um workflow com status de falha, podendo deixar o release existente com apenas os assets dos alvos que compilaram.

#### Scenario: Falha de compilação
- **WHEN** um alvo falha ao compilar
- **THEN** o workflow falha, os demais alvos continuam o upload (fail-fast desabilitado) e o release permanece criado com os assets disponíveis

#### Scenario: Compilação bem-sucedida de todos os alvos
- **WHEN** todos os alvos compilam com sucesso
- **THEN** o release final contém todos os binários anexados