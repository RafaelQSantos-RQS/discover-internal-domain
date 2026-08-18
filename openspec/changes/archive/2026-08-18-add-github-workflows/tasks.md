# Tasks

## 1. Workflow de CI

- [x] 1.1 Criar `.github/workflows/ci.yml` com gatilho push/PR nos branches principais, matriz de SOs (ubuntu/macos/windows) e passos: checkout, toolchain stable com `components: clippy, rustfmt`, rust-cache, `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo build`, `cargo test`

## 2. Workflow de release

- [x] 2.1 Criar `.github/workflows/release.yml` com gatilho tags `v[0-9]+.*`, job `create-release` (create-gh-release-action, `contents: write`) e job `upload-assets` com matriz de 6 targets (linux/macos/windows × amd64/arm64) usando upload-rust-binary-action (`bin: dnsbrute`, `tar: unix`, `zip: windows`)

## 3. Validação

- [x] 3.1 Validar sintaxe YAML dos dois workflows e conferir nomes de actions, `permissions: contents: write` nos jobs de release e `components: clippy, rustfmt` no setup do toolchain