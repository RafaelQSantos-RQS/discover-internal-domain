## Why

O brute-force exaustivo é caro (1.9M combinações para `-m 4`) e o usuário não tem controle sobre o ponto de partida nem uma forma prática de testar nomes conhecidos. Em testes reais, `found 0` enganava porque ranges curtos não cobrem nomes como `www` (3 chars) — faltava wordlist, tamanho mínimo de início e o domínio raiz.

## What Changes

- **Modo wordlist** (`-f`/`--wordlist`): carregar subdomínios de um arquivo (1 por linha, ignora `#` e linhas vazias), substituindo a geração exaustiva; checkpoint/resume por índice de linha
- **Tamanho mínimo de geração** (`--min-len N`): o gerador exaustivo começa em comprimento N em vez de 1, pulando ranges curtos (ex.: `--min-len 3` evita testar `a`, `aa`, etc.)
- **Incluir domínio raiz** (`--include-root`): resolve e reporta o próprio domínio alvo, além dos subdomínios (relevante para assets internos onde o raiz é um host real)
- **Progresso ao vivo**: linha única em stderr atualizada a cada 1s com tempo decorrido, total verificado/percentual, qps e contagem de found

## Capabilities

### New Capabilities
Nenhuma.

### Modified Capabilities
- `cli`: novas opções (`-f/--wordlist`, `--min-len`, `--include-root`) com validação; saída de progresso ao vivo em stderr durante a enumeração
- `generation`: modo wordlist (fonte alternativa de jobs) e comprimento mínimo de geração

## Impact

- `src/cli.rs`: 3 novas flags + validação
- `src/generator.rs`: `WordlistGenerator` + enum `JobSource` + campo `min_len` no `Generator`
- `src/main.rs`: integração do JobSource no pipeline, lookup do raiz com `--include-root`, task de progresso
- Sem mudanças de dependências; formato de checkpoint compatível (wordlist usa `last_index[0]` como índice de linha)
