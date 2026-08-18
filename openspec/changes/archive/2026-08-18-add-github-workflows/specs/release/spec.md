## Purpose

Publicação de binários compilados do dnsbrute (Linux, macOS e Windows) como GitHub Release em tags versionadas.

## ADDED Requirements

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
O workflow SHALL falhar se qualquer alvo não compilar, sem publicar um release parcial.

#### Scenario: Falha de compilação
- **WHEN** um alvo falha ao compilar
- **THEN** o workflow falha e nenhum release é publicado