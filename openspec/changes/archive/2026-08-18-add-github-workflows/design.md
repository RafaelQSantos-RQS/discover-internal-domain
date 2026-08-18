## Context

O repositório foi reescrito de Go para Rust e os workflows `.github/` antigos foram removidos. O projeto está sem CI/CD. Ver proposal.md para motivação e specs/ para os requisitos de comportamento.

## Goals / Non-Goals

**Goals:**
- CI que valida fmt, clippy, build e test em push/PR, nos 3 SOs.
- Release que publica binários Linux/macOS/Windows (amd64/arm64) em tags `v*`.
- Workflows mínimos, usando actions padrão da comunidade Rust.

**Non-Goals:**
- Publicação em crates.io.
- Testes de integração com serviços externos.
- Cobertura de código (codecov) — não existia antes.

## Decisions

### 1. Toolchain: `dtolnay/rust-toolchain@stable` + `components: clippy, rustfmt`
Action padrão para instalar Rust. O profile `minimal` (default) NÃO inclui clippy/rustfmt — é obrigatório passar `components: clippy, rustfmt`.
- **Alternativa considerada**: `actions-rs/toolchain` — descontinuada. Rejeitada.

### 2. CI: matriz de SOs com 4 passos
Matriz `ubuntu-latest` / `macos-latest` / `windows-latest`, com passos: `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo build`, `cargo test`. Falha em qualquer passo interrompe o workflow (comportamento default do GitHub Actions).
- **Alternativa considerada**: rodar só em ubuntu — não valida portabilidade. Rejeitada (spec exige matriz).

### 3. Release: `taiki-e/create-gh-release-action@v1` + `taiki-e/upload-rust-binary-action@v1`
O `upload-rust-binary-action` (renomeado de `upload-rust-binary`; o nome antigo dá 404) compila e anexa os binários, mas NÃO cria o release — o `create-gh-release-action` cria. Ambos exigem `permissions: contents: write`.
- **Matriz de targets** (não existe input `targets`; usa-se `target` por job):
  - `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu` → `ubuntu-latest`
  - `x86_64-apple-darwin`, `aarch64-apple-darwin` → `macos-latest` (macOS não cross-compila a partir de ubuntu)
  - `x86_64-pc-windows-msvc`, `aarch64-pc-windows-msvc` → `windows-latest`
- `tar: unix`, `zip: windows` para empacotar por plataforma.
- **Alternativa considerada**: `softprops/action-gh-release` + build manual — mais YAML e manutenção. Rejeitada.

### 4. Cache: `Swatinem/rust-cache@v2`
Cacheia dependências entre execuções, reduzindo o tempo de CI. Uma linha, padrão da comunidade.
- **Alternativa considerada**: sem cache — builds ~1-2min a mais por execução. Aceitável, mas o cache é barato.

### 5. Checkout: `actions/checkout@v6`
Versão estável atual do checkout, usada em ambos os workflows.

## Risks / Trade-offs

- [macOS arm64 não cross-compila de ubuntu] → Matriz mapeia targets macOS para `macos-latest` (build nativo).
- [clippy/rustfmt ausentes no profile minimal] → `components: clippy, rustfmt` explícito no setup.
- [Nome antigo da action de upload dá 404] → Usar `taiki-e/upload-rust-binary-action@v1` (nome novo).
- [Release exige permissão de escrita] → `permissions: contents: write` nos jobs de release.
- [Versões de actions mudam] → Usar major tags (`@v1`, `@stable`, `@v6`) e revisar periodicamente.

## Migration Plan

- Adicionar `.github/workflows/ci.yml` e `.github/workflows/release.yml` do zero.
- Rollback: remover os arquivos (não há infraestrutura externa afetada).

## Open Questions

Nenhuma. Versões exatas de actions (patch) podem ser pinadas depois sem afetar specs, design ou tasks.