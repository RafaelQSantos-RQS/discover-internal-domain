## Context

O projeto atual é um binário Go (`dnsbrute`) com TUI (charmbracelet), worker pool, checkpoint, cache negativo e detecção de wildcard. A reescrita em Rust mantém paridade total de features, remove a TUI e usa CLI nova com clap. Ver proposal.md para motivação e specs/ para os requisitos de comportamento.

## Goals / Non-Goals

**Goals:**
- Binário Rust único, CLI-only, com paridade de features do Go.
- Concorrência via tokio com worker pool e canal de jobs com buffer limitado.
- Checkpoint com mesmo schema JSON do Go (permite reutilizar checkpoints existentes).
- Dependências mínimas e idiomáticas.

**Non-Goals:**
- Compatibilidade de flags com a versão Go (breaking, decisão do usuário).
- TUI ou qualquer saída interativa.
- Suporte a wordlists externas ou resolução via TCP/DoH (não existia no Go).

## Decisions

### 1. Runtime: tokio (multi-thread)
DNS async (hickory-resolver) exige um runtime async; tokio é o padrão da comunidade e dá controle de timeout por consulta e cancelamento via `tokio::select!`.
- **Alternativa considerada**: threads std + `getaddrinfo` bloqueante — serializa no resolver do sistema, sem timeout por consulta confiável. Rejeitada.

### 2. DNS: hickory-resolver
Resolução async A/AAAA lendo `/etc/resolv.conf`, com timeout por consulta. Equivalente ao `net.Resolver{PreferGo: true}` do Go.
- **Alternativa considerada**: `tokio::net::lookup_host` — usa pool bloqueante do sistema, sem controle fino de timeout. Rejeitada.

### 3. CLI: clap (derive)
Pedido explícito do usuário. Derive API mantém o parsing declarativo e gera `--help` automaticamente.

### 4. Fila de jobs: async_channel (bounded, MPMC)
Um produtor (gerador) e N consumidores (workers) precisam de canal MPMC com buffer limitado. `async_channel` é a opção mínima e idiomática.
- **Alternativa considerada**: `tokio::sync::mpsc` + `Arc<Mutex<Receiver>>` — funciona mas é feio e propenso a deadlock. Rejeitada.

### 5. Checkpoint: serde_json + escrita atômica (temp + rename + sync)
Mesmo schema JSON do Go (`completed`, `last_index`, `length`, `timestamp`, `max_len`, `domain`, `wildcard_ips`), permissões 0600, validação de domínio/max_len ao carregar. Nome do temp file derivado de pid + contador (saves são serializados por mutex, sem colisão).
- **Alternativa considerada**: `tempfile` crate — dependência extra para o que poucas linhas resolvem. Rejeitada.

### 6. Cache negativo: HashMap + VecDeque + Mutex
TTL via `Instant`, evicção FIFO das entradas mais antigas ao atingir 100k (mesmo comportamento do Go), limpeza periódica de expirados.
- **Alternativa considerada**: crates `lru`/`moka` — dependências extras para o mesmo comportamento. Rejeitada.

### 7. Modelo de concorrência
Pipeline: task produtora (gerador, `next()` iterativo) → `async_channel` bounded → N tasks workers (`tokio::spawn`) → resultados via callback para stdout. Contador atômico (`AtomicU64`) para `completed`. Checkpoint salvo periodicamente (10s) e no shutdown via `tokio::signal`.

### 8. Estrutura de módulos
```
src/
  main.rs        # entry, pipeline (produtor → canal → workers), signals, resumo
  cli.rs         # clap args + validação
  generator.rs   # gerador iterativo de combinações (com retomada)
  resolver.rs    # lookup DNS + detecção/filtragem de wildcard
  negcache.rs    # cache negativo (HashMap + VecDeque)
  checkpoint.rs  # save/load atômico + validação
```

## Risks / Trade-offs

- [API do hickory-resolver muda entre versões] → Fixar versão no Cargo.toml e consultar docs da versão pinada.
- [Comportamento do resolver difere do Go (timeouts, ordem de IPs)] → Timeout por consulta e workers configuráveis mitigam; ordem de IPs não é contratual.
- [Checkpoints Go podem não carregar se schema divergir] → Schema mantido idêntico; se divergir, erro claro e início do zero (comportamento já especificado).
- [Remoção da TUI muda a UX] → Decisão explícita do usuário; saída texto puro é o novo contrato.

## Migration Plan

- Substituição total: remover `main.go`, `core/`, `state/`, `tui/`, `go.mod`, `go.sum`; adicionar `Cargo.toml` e `src/`.
- Rollback: `git revert` do commit da reescrita (o histórico Go permanece no git).

## Open Questions

Nenhuma. Decisões deferíveis (ex.: pinar versão exata do hickory-resolver) são resolvidas na implementação sem afetar specs, design ou tasks.