## Context

Auditoria de specs vs código (2026-08-18) identificou dois contratos divergentes da implementação. Ver proposal.md para o detalhamento. Nenhuma mudança de código é necessária — o drift é exclusivamente de spec.

## Goals / Non-Goals

**Goals:**
- Alinhar as specs `negative-cache` e `release` ao comportamento real
- Manter o comportamento observável descrito (evicção das mais antigas; workflow falho em falha de alvo)

**Non-Goals:**
- Mudar o código (`negcache.rs` já é FIFO e documentado como tal)
- Mudar o workflow de release (padrão taiki-e: create-release antes do upload é o comportamento desejado — assets parciais em falha são aceitáveis e o status do workflow sinaliza o problema)

## Decisions

### FIFO em vez de LRU na spec de cache
O código evicta via `VecDeque::pop_front` (ordem de inserção). Com TTL uniforme, a entrada mais antiga a entrar é a primeira a expirar, então FIFO e LRU são equivalentes no comportamento observável. A spec passa a descrever o que o código faz.
- **Alternativa rejeitada**: implementar LRU real (mover para o fim da fila em cada hit) — complexidade sem ganho observável com TTL uniforme.

### Release: spec descreve o fluxo real, não o idealizado
O workflow usa `create-gh-release-action` (cria o release) seguido de `upload-rust-binary-action` em matrix com `fail-fast: false`. Falha de um alvo não desfaz o release já criado. A spec passa a exigir apenas que o workflow falhe nesse caso, documentando a possibilidade de assets parciais.
- **Alternativa rejeitada**: reordenar o workflow para compilar tudo antes de criar o release — exigiria reescrever o fluxo taiki-e para um caso que nunca ocorreu; o status de falha do workflow já sinaliza o problema.

## Risks / Trade-offs

- Spec de release menos estrita que antes → Mitigação: o cenário documenta explicitamente o comportamento; se assets parciais se tornarem um problema real, o workflow pode ser reordenado (decisão registrada acima).

## Migration Plan

N/A — mudança de contrato documental; sem deploy.

## Open Questions

Nenhuma.