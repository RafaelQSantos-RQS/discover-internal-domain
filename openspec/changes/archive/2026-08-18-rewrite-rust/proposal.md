## Why

O projeto atual (`dnsbrute`) é escrito em Go e acumula complexidade de uma TUI (charmbracelet) que não é mais desejada. O usuário quer reescrever o projeto inteiro do zero em Rust — sua stack favorita — mantendo paridade total de features, mas com uma CLI limpa (sem TUI) e interface de linha de comando nova (clap), sem compromisso de compatibilidade com as flags atuais.

## What Changes

- **BREAKING**: Reescreve todo o código de Go para Rust (binário `dnsbrute` em Rust).
- **BREAKING**: Remove a TUI interativa (charmbracelet/lipgloss) — modo CLI-only.
- **BREAKING**: Nova interface de linha de comando com `clap` (flags novas, sem compatibilidade com as flags Go).
- Mantém paridade total de features:
  - Geração iterativa de combinações de subdomínios (a-z, 0-9, `-`) com `maxlen` limitado a 63 (limite de label DNS).
  - Limite de combinações (`max-combinations`) para evitar exaustão de recursos.
  - Worker pool concorrente com buffer limitado de jobs.
  - Timeout por consulta DNS.
  - Detecção de wildcard via probe de subdomínio aleatório + filtragem de respostas wildcard.
  - Cache de respostas negativas (LRU, máx. 100k entradas, TTL configurável).
  - Checkpoint atômico (temp + rename + sync, permissões 0600) com validação de domínio/maxlen e retomada.
  - Graceful shutdown em SIGINT/SIGTERM.
  - Saída em stdout com resumo final.
- Remove dependências Go (`pflag`, `lipgloss`, `charmbracelet`) e arquivos Go (`main.go`, `core/`, `state/`, `tui/`, `go.mod`, `go.sum`).

## Capabilities

### New Capabilities
- `cli`: Interface de linha de comando (clap), validação de flags, saída de resultados e resumo final.
- `generation`: Geração iterativa de combinações de subdomínios com limites de comprimento e quantidade.
- `dns-resolution`: Consulta DNS com worker pool concorrente, timeout por consulta e filtragem de wildcard.
- `wildcard-detection`: Detecção de wildcard via probe de subdomínio aleatório e filtragem de respostas.
- `negative-cache`: Cache de respostas negativas (NXDOMAIN/timeout) com LRU e TTL.
- `checkpoint`: Persistência atômica de progresso com retomada e validação de configuração.

### Modified Capabilities
<!-- Nenhuma: o diretório openspec/specs/ está vazio; todas as capabilities são novas. -->

## Impact

- **Código**: Remove `main.go`, `core/`, `state/`, `tui/`, `go.mod`, `go.sum`. Adiciona projeto Rust (`Cargo.toml`, `src/`).
- **Dependências**: Remove `pflag`, `lipgloss`, `charmbracelet`. Adiciona `clap`, `tokio`, `hickory-dns` (ou `trust-dns`), `serde`/`serde_json`.
- **CLI**: Flags novas via clap; scripts existentes que usam as flags Go quebram (breaking).
- **Comportamento**: Sem TUI; saída texto puro em stdout; resumo final em stderr.
- **Build**: `cargo build`/`cargo run` substituem `go build`/`go run`.