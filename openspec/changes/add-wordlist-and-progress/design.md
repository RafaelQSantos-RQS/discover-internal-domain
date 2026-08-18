## Context

A enumeração usa um gerador exaustivo baseado em odômetro (`Generator` em `src/generator.rs`) que produz `37^len` combinações por comprimento, consumido por um pipeline produtor → canal → workers. Checkpoints salvam `last_index` por comprimento. O projeto segue a arquitetura do AGENTS.md (módulos pequenos, `Result<T, String>`, tokio). O push anterior já trazia o motor raw UDP (socket per query).

## Goals / Non-Goals

**Goals:**
- Wordlist como fonte alternativa de jobs sem repetir o pipeline (mesmo canal, workers, checkpoint)
- Geração exaustiva com ponto de partida configurável (`min_len`)
- Inclusão opcional do domínio raiz no reporte
- Feedback de progresso sem poluir o stdout (resultados) nem o resumo

**Non-Goals:**
- Permutação de wordlist (adicionar sufixos/prefixos às linhas)
- Fontes passivas (crt.sh, etc.)
- Saída JSON

## Decisions

### JobSource enum unifica brute e wordlist
`Generator` vira `enum JobSource { Brute(Generator), Wordlist(WordlistGenerator) }` com `next()`, `total()` e `last_index()`. O pipeline consome `JobSource`, sem saber a origem.
- **Alternativa rejeitada**: separar pipelines por modo — duplicaria main.rs e o checkpoint. Um enum preserva o pipeline único.

### WordlistGenerator por índice, não por iterador de linha
`WordlistGenerator` lê o arquivo para `Vec<String>` na construção e avança por índice (`last_index`), em vez de um `Lines` iterator. O checkpoint de wordlist guarda `last_index[0]` e reusa o formato existente — o resume vira "seek por índice" em vez de re-ler o arquivo até a posição.
- **Trade-off**: carrega o arquivo inteiro em memória. Wordlists de brute-force interno são pequenas (centenas a dezenas de milhares de linhas); aceitável.
- **Detalhe de checkpoint**: em modo wordlist o checkpoint grava `max_len: 0`; no load, `expected_max_len = 0` indica wordlist e resume por `last_index.first()`.

### min_len no Generator, não filtragem pós-hoc
`Generator` ganha `min_len` (`clamp(1, max_len)`); `total()` soma `min_len..=max_len` e o resume seta `min_len: 1` (um checkpoint salvo antes desta feature pode ter índices de comprimentos baixos). O progresso usa `total()` — por isso mostra 50653 com `--min-len 3 -m 3` em vez de 52059.

### --include-root resolve fora do gerador
O raiz não é um job gerado (`format!("{comb}.{domain}")` nunca produz o raiz). `main.rs` faz um `resolver::lookup(&engine, &args.domain)` direto, sem filtro de wildcard (é o alvo explícito), reporta no mesmo formato `fqdn -> cname -> ips` e incrementa o contador de found.

### Progresso via task com `\r` em stderr
Uma `tokio::task` com `interval(1s)` escreve uma única linha em stderr sobrescrita com `\r`: `[elapsed] checked/total (pct%) qps | found: N`. Um `eprintln!()` quebra a linha antes do resumo final (que vai para stdout).
- **Alternativa rejeitada**: `indicatif` — dependência nova para algo que `\r` resolve em 20 linhas.

## Risks / Trade-offs

- Wordlist grande em memória (toda lida para `Vec<String>`) → Mitigação: validação requer arquivo legível; para uso interno o tamanho é trivial. Se um dia passar de ~1M linhas, trocar por seek por índice com `BufReader` + contagem de bytes.
- Checkpoint antigo (pré-min_len) com índices de comprimentos baixos → Mitigação: resume seta `min_len: 1`, cobrindo o range completo.
- `\r` em stderr pode confundir captura de logs → Mitigação: linha quebrada antes do resumo; scripts que capturam stderr veem métricas finais por linha.

## Migration Plan

N/A — ferramenta CLI local, sem deploy. Checkpoints antigos continuam válidos (resume cobre o range completo).

## Open Questions

Nenhuma.
