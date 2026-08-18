## Why

Auditoria de specs vs código (2026-08-18) encontrou dois contratos que descrevem comportamento que a implementação não entrega: a spec de cache negativo promete evicção LRU quando o código usa FIFO, e a spec de release promete "nenhum release publicado" em falha quando o workflow (padrão taiki-e) cria o release antes do upload. As specs devem descrever o comportamento real — corrigir o contrato, não o código.

## What Changes

- **negative-cache**: "Limite de entradas" passa a especificar evicção **FIFO** (ordem de inserção) em vez de LRU — o comportamento observável (remover as entradas mais antigas quando o limite é atingido) é mantido; TTL uniforme torna FIFO e LRU equivalentes na prática
- **release**: "Falha interrompe o release" passa a especificar o comportamento real: o release é criado antes do upload dos assets; falha de um alvo SHALL marcar o workflow como falho, podendo deixar assets parciais anexados

## Capabilities

### New Capabilities
Nenhuma.

### Modified Capabilities
- `negative-cache`: evicção LRU → FIFO na requirement "Limite de entradas"
- `release`: semântica de falha na requirement "Falha interrompe o release" alinhada ao workflow real

## Impact

- Somente arquivos de spec (`openspec/specs/negative-cache/spec.md`, `openspec/specs/release/spec.md`); nenhuma mudança de código, workflow ou dependências
- Comentário de doc no código (`negcache.rs`) que diz "FIFO eviction" já é correto — o drift era exclusivamente da spec
