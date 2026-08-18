## 1. Correção de specs

- [x] 1.1 Atualizar delta `negative-cache`: evicção FIFO (ordem de inserção) no lugar de LRU
- [x] 1.2 Atualizar delta `release`: falha de alvo marca o workflow como falho, release pode permanecer com assets parciais

## 2. Sync e validação

- [x] 2.1 Sincronizar deltas para as main specs (`negative-cache`, `release`)
- [x] 2.2 `openspec validate --specs` com 8/8 specs válidas
- [x] 2.3 Confirmar que nenhum código mudou (`git status` limpo fora de `openspec/`)