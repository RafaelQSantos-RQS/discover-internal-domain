## Why

O throughput atual é limitado pelo stack completo do `hickory-resolver` (config de sistema, hosts file, cache interno, retries, failover) — overhead por consulta que não faz sentido para brute-force, onde a maioria das queries é NXDOMAIN. O objetivo é o salto de performance estilo massdns: pacotes DNS crus via UDP, sem o resolver completo, com pool de resolvers e workers adaptativos.

## What Changes

- **BREAKING**: Substitui o caminho de consulta do `hickory-resolver` por um motor DNS raw UDP (estilo massdns): pacotes crus via socket UDP, parsing próprio, retry com timeout, fallback TCP para respostas truncadas.
- **BREAKING**: Remove a dependência `hickory-resolver` do caminho de consulta (substituída por `hickory-proto` para encode/decode do wire format).
- Adiciona **pool de resolvers** com round-robin: resolvers do system config por default, com flag `-r` para lista customizada.
- Adiciona **writer task**: workers enviam resultados por canal para uma task dedicada de escrita, eliminando contenção de `Mutex` na saída.
- Adiciona **detecção de wildcard robusta**: N probes aleatórios (default 3) em vez de 1, com união dos IPs.
- Adiciona **seguimento de CNAME**: respostas com CNAME são resolvidas e o alvo do CNAME é reportado junto com os IPs.
- Adiciona **workers adaptativos**: ajuste dinâmico do número de workers baseado na latência das respostas.
- Adiciona flag `-r`/`--resolvers` (arquivo com lista de DNS servers).

## Capabilities

### New Capabilities
<!-- Nenhuma capability nova: todas as mudanças são em capabilities existentes. -->

### Modified Capabilities
- `dns-resolution`: motor raw UDP, pool de resolvers, seguimento de CNAME, workers adaptativos.
- `wildcard-detection`: detecção robusta com N probes.
- `cli`: nova flag `-r`/`--resolvers`.

## Impact

- **Código**: novo módulo de motor DNS raw UDP (`src/dnsengine.rs` ou similar); `resolver.rs` reescrito; `main.rs` com writer task e workers adaptativos; `cli.rs` com flag `-r`.
- **Dependências**: remove `hickory-resolver`; adiciona `hickory-proto` (wire format) e `rand` (já presente) para probes.
- **Comportamento**: throughput significativamente maior (objetivo 10-100x); resultados com CNAME incluem o alvo; wildcard detectado com mais probes.
- **Compatibilidade**: flags existentes mantidas; `-r` é aditiva. Sem mudança no formato de saída.