# Tasks

## 1. Motor DNS raw UDP (`dnsengine.rs`)

- [x] 1.1 Criar `src/dnsengine.rs` com construção de queries A/AAAA via `hickory-proto` (`Message::new` + `add_query` + `to_vec`), envio/recepção UDP com timeout, validação de transaction ID e retry (default 2 tentativas) em timeout/SERVFAIL
- [x] 1.2 Adicionar pool de resolvers: parse de `/etc/resolv.conf` (unix), fallback `8.8.8.8`+`1.1.1.1` (windows), carregamento de arquivo `-r` (IP ou IP:porta por linha) e distribuição round-robin via `AtomicUsize`
- [x] 1.3 Adicionar fallback TCP para respostas truncadas (bit TC): framing manual de 2 bytes (RFC 1035 §4.2.2) com tokio

## 2. Resolver reescrito (`resolver.rs`)

- [x] 2.1 Reescrever `resolver.rs` para usar o motor: lookup A+AAAA em paralelo com IPs mesclados, extração de CNAME da resposta e follow-up de 1 nível quando só houver CNAME
- [x] 2.2 Implementar detecção de wildcard robusta: N probes aleatórios (default 3) com união dos IPs, mantendo restauração via checkpoint e flag `-W`

## 3. Pipeline e CLI (`main.rs`, `cli.rs`)

- [x] 3.1 Adicionar flag `-r`/`--resolvers` em `cli.rs` com validação (arquivo legível com pelo menos um resolver válido)
- [x] 3.2 Implementar writer task: workers enviam resultados por `async_channel` para task dedicada que possui a saída (stdout ou arquivo), removendo o `Mutex<Box<dyn Write>>`
- [x] 3.3 Implementar workers adaptativos: controller task a cada 1s ajusta `target_workers` (1..=max) via EMA da latência; workers checam o alvo antes de processar job

## 4. Dependências e validação

- [x] 4.1 Atualizar `Cargo.toml`: remover `hickory-resolver`, adicionar `hickory-proto = "0.26"`
- [x] 4.2 Atualizar/criar testes unitários para `dnsengine` (build de query, parse de resposta, round-robin) e `resolver` (CNAME, wildcard N probes)
- [x] 4.3 Validar: `cargo build`, `cargo test`, `cargo clippy -- -D warnings`, `cargo fmt --check` e benchmark de qps antes/depois para confirmar o ganho de performance