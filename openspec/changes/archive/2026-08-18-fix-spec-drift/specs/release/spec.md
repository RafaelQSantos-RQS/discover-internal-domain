## MODIFIED Requirements

### Requirement: Falha interrompe o release
O workflow SHALL criar o GitHub Release para a tag antes de anexar os assets e SHALL falhar se qualquer alvo não compilar. Como o release é criado antes do upload, uma falha de alvo SHALL resultar em um workflow com status de falha, podendo deixar o release existente com apenas os assets dos alvos que compilaram.

#### Scenario: Falha de compilação
- **WHEN** um alvo falha ao compilar
- **THEN** o workflow falha, os demais alvos continuam o upload (fail-fast desabilitado) e o release permanece criado com os assets disponíveis

#### Scenario: Compilação bem-sucedida de todos os alvos
- **WHEN** todos os alvos compilam com sucesso
- **THEN** o release final contém todos os binários anexados
