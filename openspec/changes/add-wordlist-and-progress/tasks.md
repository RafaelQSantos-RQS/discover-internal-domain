## 1. Modo wordlist

- [x] 1.1 Implementar `WordlistGenerator` em generator.rs: ler arquivo por linha, ignorar vazias e comentários `#`, avançar por índice
- [x] 1.2 Criar enum `JobSource` (Brute/Wordlist) com interface unificada `next()`, `total()`, `last_index()`
- [x] 1.3 Adicionar flag `-f/--wordlist` em cli.rs com validação (arquivo legível, ≥1 entrada)
- [x] 1.4 Integrar `JobSource` no pipeline do main.rs (produtor → canal → workers)
- [x] 1.5 Checkpoint em modo wordlist: gravar `max_len: 0`, retomar por índice de linha (`last_index[0]`)

## 2. Comprimento mínimo de geração

- [x] 2.1 Adicionar campo `min_len` ao `Generator`: `total()` soma `min_len..=max_len`; `resume()` seta `min_len: 1` para checkpoints antigos
- [x] 2.2 Adicionar flag `--min-len` em cli.rs com validação (`1 <= min_len <= maxlen`)
- [x] 2.3 Atualizar main.rs para `Generator::new(max_len, min_len, max_combs)`

## 3. Domínio raiz

- [x] 3.1 Adicionar flag `--include-root` em cli.rs
- [x] 3.2 main.rs: resolver o raiz via `resolver::lookup` (sem filtro de wildcard), reportar no formato `fqdn -> cname -> ips`, incrementar found

## 4. Progresso ao vivo

- [x] 4.1 Task tokio com `interval(1s)` escrevendo linha única em stderr (`\r`): elapsed, checked/total, %, qps, found
- [x] 4.2 Quebrar a linha de progresso (`eprintln!()`) antes do resumo final

## 5. Validação

- [x] 5.1 Testes de unidade para wordlist, min_len e cli (43 testes passando)
- [x] 5.2 `cargo clippy -- -D warnings` e `cargo fmt` limpos
- [x] 5.3 Validação real: `--include-root example.com` reporta o raiz com IPs; `--min-len 3 -m 3` total 50653; wordlist google.com 5/6 encontrados; resume 1157→5000 sem repetição
