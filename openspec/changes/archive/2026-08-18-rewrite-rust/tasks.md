## 1. Setup do projeto Rust

- [x] 1.1 Criar `Cargo.toml` com binário `dnsbrute` e dependências: `tokio` (rt-multi-thread, macros, signal, time), `clap` (derive), `hickory-resolver`, `serde`/`serde_json`, `async_channel`, `rand`
- [x] 1.2 Remover arquivos Go: `main.go`, `core/`, `state/`, `tui/`, `go.mod`, `go.sum`
- [x] 1.3 Criar estrutura `src/`: `main.rs`, `cli.rs`, `generator.rs`, `resolver.rs`, `negcache.rs`, `checkpoint.rs`
- [x] 1.4 Verificar build: `cargo build` compila sem erros

## 2. CLI (clap)

- [x] 2.1 Definir struct de args com clap derive: `--domain` (obrigatório), `--maxlen`, `--workers`, `--timeout`, `--wildcard` (bool), `--out`, `--max-combinations`, `--buffer`, `--checkpoint`, `--cache-ttl`
- [x] 2.2 Implementar validação: domain obrigatório, maxlen 1..=63 (cap em 63), workers >= 1, buffer >= 1, cache-ttl >= 0
- [x] 2.3 Implementar saída de resultados em stdout (`fqdn -> ip1,ip2`) e resumo final em stderr
- [x] 2.4 Testes unitários para parsing e validação de args

## 3. Gerador de combinações

- [x] 3.1 Implementar `Generator` iterativo (alfabeto `a-z0-9-`, comprimentos 1..=maxlen, ordem lexicográfica) com método `next()`
- [x] 3.2 Implementar limite de combinações (`max_combs`) e limite de comprimento (cap 63)
- [x] 3.3 Implementar retomada a partir de checkpoint (restaurar `last_index` + `length`)
- [x] 3.4 Testes unitários: contagem de combinações por comprimento, progressão de comprimento, retomada

## 4. Resolução DNS e wildcard

- [x] 4.1 Implementar lookup DNS async com hickory-resolver e timeout por consulta
- [x] 4.2 Implementar detecção de wildcard: probe de subdomínio aleatório (12 chars) e registro do conjunto de IPs
- [x] 4.3 Implementar filtragem: descartar respostas cujos IPs pertencem integralmente ao padrão wildcard
- [x] 4.4 Implementar restauração de wildcard a partir de checkpoint e opção de desabilitar detecção
- [x] 4.5 Testes unitários para filtragem wildcard (total, parcial, ausente)

## 5. Cache negativo

- [x] 5.1 Implementar `NegCache` com `HashMap<String, Instant>` + `VecDeque` (evicção FIFO, máx. 100k, TTL)
- [x] 5.2 Implementar limpeza periódica de entradas expiradas
- [x] 5.3 Testes unitários: cache hit dentro do TTL, expiração, evicção no limite, TTL zero desabilita

## 6. Checkpoint

- [x] 6.1 Implementar structs serde com schema JSON do Go (`completed`, `last_index`, `length`, `timestamp`, `max_len`, `domain`, `wildcard_ips`)
- [x] 6.2 Implementar save atômico (temp + rename + sync, permissões 0600)
- [x] 6.3 Implementar load com validação de domínio e max_len (rejeitar com erro se incompatível)
- [x] 6.4 Testes unitários: round-trip save/load, escrita atômica, rejeição por mismatch

## 7. Pipeline de orquestração (main.rs)

- [x] 7.1 Montar pipeline: task produtora (gerador) → `async_channel` bounded → N tasks workers (`tokio::spawn`)
- [x] 7.2 Implementar contador atômico de combinações concluídas e limite de combinações
- [x] 7.3 Implementar salvamento periódico de checkpoint (10s) e final no shutdown
- [x] 7.4 Implementar graceful shutdown via `tokio::signal` (SIGINT/SIGTERM)
- [x] 7.5 Integrar saída de resultados e resumo final
- [x] 7.6 Teste de integração: execução curta (`--maxlen=1`) com e sem checkpoint, com e sem wildcard

## 8. Documentação

- [x] 8.1 Atualizar README: instalação (`cargo build`), uso com novas flags clap, opções, features
- [x] 8.2 Atualizar AGENTS.md: comandos de build/test/lint para Rust (`cargo build`, `cargo test`, `cargo fmt`, `cargo clippy`)
- [x] 8.3 Verificação final: `cargo build`, `cargo test`, `cargo clippy` sem warnings