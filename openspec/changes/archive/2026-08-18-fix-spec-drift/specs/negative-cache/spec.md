## MODIFIED Requirements

### Requirement: Limite de entradas
O cache SHALL limitar o número de entradas a 100.000, evictando as entradas mais antigas em ordem de inserção (FIFO) quando o limite é atingido.

#### Scenario: Limite atingido
- **WHEN** o cache atinge 100.000 entradas e uma nova entrada é adicionada
- **THEN** a entrada adicionada primeiro é removida para acomodar a nova
