## Purpose

Validação contínua do projeto Rust (dnsbrute) em push e pull requests, garantindo formatação, lint, build e testes antes de qualquer merge.

## ADDED Requirements

### Requirement: Gatilho de execução
O workflow de CI SHALL executar em pushes e pull requests para os branches principais do repositório.

#### Scenario: Push para branch principal
- **WHEN** um push é feito para um branch principal
- **THEN** o workflow de CI é executado

#### Scenario: Pull request aberto
- **WHEN** um pull request é aberto ou atualizado para um branch principal
- **THEN** o workflow de CI é executado

### Requirement: Verificação de formatação
O workflow SHALL verificar a formatação com `cargo fmt --check`; código não formatado SHALL falhar o workflow.

#### Scenario: Código não formatado
- **WHEN** o código não está formatado conforme o rustfmt
- **THEN** o workflow falha com erro de formatação

### Requirement: Verificação de lint
O workflow SHALL executar `cargo clippy -- -D warnings`; qualquer warning SHALL falhar o workflow.

#### Scenario: Warning de clippy
- **WHEN** o clippy emite qualquer warning
- **THEN** o workflow falha

### Requirement: Build e testes
O workflow SHALL compilar o projeto com `cargo build` e executar todos os testes com `cargo test`; falhas SHALL interromper o workflow.

#### Scenario: Teste falha
- **WHEN** um teste falha
- **THEN** o workflow falha e o pull request não pode ser mergeado

#### Scenario: Build falha
- **WHEN** o projeto não compila
- **THEN** o workflow falha

### Requirement: Matriz de sistemas operacionais
O workflow SHALL executar a validação em Linux, macOS e Windows para garantir portabilidade.

#### Scenario: Execução multiplataforma
- **WHEN** o workflow é executado
- **THEN** a validação roda em Linux, macOS e Windows