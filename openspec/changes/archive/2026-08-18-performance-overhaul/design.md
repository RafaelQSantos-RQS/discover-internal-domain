## Context

O throughput atual é limitado pelo stack completo do `hickory-resolver` (config de sistema, hosts file, cache interno, retries, failover). O objetivo é o salto de performance estilo massdns: pacotes DNS crus via UDP, sem resolver completo, com pool de resolvers, writer task, wildcard robusto, CNAME e workers adaptativos. Ver proposal.md e specs/ para requisitos.

## Goals / Non-Goals

**Goals:**
- Motor DNS raw UDP (massdns-style) substituindo o caminho de consulta do hickory-resolver.
- Pool de resolvers (system config + `-r`) com round-robin.
- Writer task (canal em vez de Mutex na saída).
- Wildcard robusto (N probes), seguimento de CNAME, workers adaptativos.
- Preservar comportamento observável: formato de saída, checkpoint, flags existentes.

**Non-Goals:**
- Wordlist, permutação, fontes passivas (outros changes).
- EDNS/DO (DNSSEC) — queries mínimas sem OPT record.
- Suporte a DNS sobre TLS/HTTPS.

## Decisions

### 1. Wire format: `hickory-proto` 0.26.1 (encode/decode puro)
`hickory-proto` 0.26 é apenas a camada de encode/decode (sem tokio, sem `MessageBuilder`, sem `TcpClientStream` — movidos para `hickory-net`). É exatamente o que precisamos: montar queries e parsear respostas, gerenciando sockets/retries/pool nós mesmos.
- Query: `Message::new(id, MessageType::Query, OpCode::Query)` + `add_query(Query::query(name, qtype))` + `metadata.recursion_desired = true` + `to_vec()`.
- Parse: `Message::from_vec(&buf)`; campos pub via Deref: `msg.truncation`, `msg.response_code`, `msg.answers`, `msg.id`.
- **Alternativa considerada**: escrever wire format do zero — mais código e risco de bugs. Rejeitada.

### 2. Motor UDP: um socket por query (não compartilhado)
Cada query cria UM socket UDP não-conectado próprio. Por query: escolhe resolver (round-robin), monta query com ID aleatório, `send_to`, `recv_from` com timeout, valida ID da transação.
- **Por que socket por query (e não por worker)**: A+AAAA rodam em paralelo via `tokio::join!` no mesmo FQDN. Com um socket compartilhado, duas tasks concorrentes em `recv_from` podem roubar o pacote uma da outra (ID mismatch → loop → timeout de ambos). Isso foi observado em teste real: 4 de 8 workers timeouting a 2s. Socket por query elimina a corrida; o custo de `socket()+bind()` (~µs) é irrelevante frente ao RTT de rede.
- Retry: timeout ou SERVFAIL → nova tentativa (default 2 tentativas) com o próximo resolver.
- Fallback TCP: bit TC setado → refazer via TCP com framing manual de 2 bytes (RFC 1035 §4.2.2, ~10 linhas com tokio). Evita dependência `hickory-net`.
- Dual-stack: queries A e AAAA em paralelo por FQDN, IPs mesclados (preserva comportamento atual do `lookup_ip`).

### 3. Pool de resolvers: system config + `-r`, round-robin
- Default: parseia `/etc/resolv.conf` (unix). Windows: fallback para `8.8.8.8` + `1.1.1.1` (sem resolv.conf; `-r` recomendado).
- `-r arquivo`: lê uma linha por resolver (IP ou IP:porta).
- Distribuição: `AtomicUsize` round-robin compartilhado entre workers.
- **Alternativa considerada**: manter hickory-resolver só para system config — dependência desnecessária. Rejeitada.

### 4. Writer task: canal em vez de Mutex
Workers enviam linhas de resultado por `async_channel` para uma task dedicada que possui a saída (stdout ou arquivo). Elimina contenção de `Mutex<Box<dyn Write>>` no caminho quente.
- **Alternativa considerada**: `Mutex` atual — contenção quando há muitos resultados. Rejeitada.

### 5. Wildcard robusto: N probes (default 3)
Probe N subdomínios aleatórios (default 3), união dos IPs dos que resolverem = padrão wildcard. Restauração via checkpoint e flag `-W` mantidas.

### 6. Seguimento de CNAME
Resposta com CNAME: extrai o alvo do CNAME + IPs A/AAAA da mesma resposta. Se só houver CNAME (sem IPs), faz uma query de follow-up para o alvo (1 nível). Saída: `fqdn -> cname -> ip1,ip2`.

### 7. Workers adaptativos: controller + polling
- Controller task a cada 1s: calcula EMA da latência das queries e ajusta `target_workers` (1..=max configurado) num `AtomicUsize`.
- Workers: antes de processar job, checam se `active_count >= target_workers`; se sim, dormem ~50ms e re-checam. Simples e correto o suficiente.
- **Alternativa considerada**: semaphore com permits dinâmicos — tokio não suporta alterar max. Rejeitada.

### 8. Dependências
- Remove: `hickory-resolver`.
- Adiciona: `hickory-proto = "0.26"`.
- Mantém: tokio, clap, serde/serde_json, async_channel, rand, chrono.

### 9. Estrutura de módulos
```
src/
  main.rs        # pipeline, writer task, controller adaptativo, signals, resumo
  cli.rs         # + flag -r/--resolvers
  dnsengine.rs   # NOVO: motor raw UDP, pool de resolvers, TCP fallback
  resolver.rs    # reescrito: WildcardDetector (N probes), CNAME, usa dnsengine
  generator.rs   # inalterado
  negcache.rs    # inalterado
  checkpoint.rs  # inalterado
```

## Risks / Trade-offs

- [API nova do hickory-proto 0.26 (MessageBuilder removido)] → Verificado via ExternalScout; API documentada no design.
- [Socket UDP não-conectado pode receber resposta de outro resolver] → Validação de transaction ID antes de aceitar.
- [Windows sem resolv.conf] → Fallback para resolvers públicos + `-r` recomendado.
- [Workers adaptativos com polling são aproximados] → Suficiente para o objetivo (evitar sobrecarga); refinamento futuro se necessário.
- [TCP fallback adiciona latência] → Só ocorre com bit TC (raro em respostas pequenas).
- [Dual-stack dobra tráfego] → Preserva comportamento atual; trade-off aceito.

## Migration Plan

- Implementar `dnsengine.rs` primeiro (motor isolado, testável).
- Reescrever `resolver.rs` sobre o motor.
- Ajustar `main.rs` (writer task, controller) e `cli.rs` (`-r`).
- Remover `hickory-resolver` do Cargo.toml.
- Benchmark antes/depois para validar o ganho de performance (qps).

## Open Questions

Nenhuma. Decisões de implementação (número de probes, tentativas, thresholds do adaptativo) podem ser ajustadas sem afetar specs.