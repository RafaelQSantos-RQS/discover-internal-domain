## Why

O repositório foi reescrito de Go para Rust, mas os workflows `.github/` antigos (que referenciavam Go 1.26, `go.sum`, `gofmt`) foram removidos no cleanup. O projeto está sem CI/CD — nenhum push/PR é validado e não há pipeline de release. É necessário criar os workflows do zero para a stack Rust.

## What Changes

- **BREAKING**: Remove a necessidade dos workflows Go antigos (já removidos) — os novos workflows usam a stack Rust.
- Adiciona workflow de **CI**: valida `cargo fmt --check`, `cargo clippy -D warnings`, `cargo build` e `cargo test` em push/PR.
- Adiciona workflow de **Release**: compila binários para Linux, macOS e Windows (amd64/arm64) e publica um GitHub Release em tags `v*`.
- Adiciona `.github/` do zero (sem resquícios do Go).

## Capabilities

### New Capabilities
- `ci`: Validação contínua do projeto Rust (fmt, clippy, build, test) em push e pull requests.
- `release`: Publicação de binários compilados (Linux/macOS/Windows) como GitHub Release em tags versionadas.

### Modified Capabilities
<!-- Nenhuma: os workflows anteriores foram removidos; não há capability existente a modificar. -->

## Impact

- **Código**: Adiciona `.github/workflows/ci.yml` e `.github/workflows/release.yml`.
- **Dependências**: Actions do GitHub (setup de toolchain Rust, upload de artefatos, criação de release).
- **Comportamento**: Push/PR passam a ser validados automaticamente; tags `v*` geram releases com binários.
- **Build**: `cargo` substitui `go` em todos os passos de CI/CD.