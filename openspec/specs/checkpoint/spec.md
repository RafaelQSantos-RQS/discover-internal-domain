# Checkpoint Specification

## Purpose

Persistência do progresso da enumeração em disco com escrita atômica, validação de configuração e retomada após interrupção.

## Requirements

### Requirement: Escrita atômica de checkpoint
A ferramenta SHALL salvar checkpoints de forma atômica: escrever em arquivo temporário no mesmo diretório, sincronizar com o disco e renomear sobre o arquivo final. O arquivo SHALL ter permissões 0600.

#### Scenario: Salvamento de checkpoint
- **WHEN** a ferramenta salva um checkpoint
- **THEN** o arquivo final contém o estado completo e é criado via temp + rename atômico com permissões 0600

### Requirement: Conteúdo do checkpoint
O checkpoint SHALL conter: contagem de combinações concluídas, último índice e comprimento da geração, domínio alvo, comprimento máximo configurado e IPs wildcard detectados (quando houver).

#### Scenario: Leitura de checkpoint salvo
- **WHEN** um checkpoint é carregado
- **THEN** todos os campos salvos estão disponíveis para retomada

### Requirement: Validação de configuração ao carregar
A ferramenta SHALL rejeitar um checkpoint cujo domínio ou comprimento máximo não corresponda à configuração atual da execução.

#### Scenario: Domínio incompatível
- **WHEN** o checkpoint foi salvo para um domínio diferente do atual
- **THEN** o checkpoint é rejeitado com erro e a enumeração inicia do zero

#### Scenario: Comprimento máximo incompatível
- **WHEN** o checkpoint foi salvo com comprimento máximo diferente do atual
- **THEN** o checkpoint é rejeitado com erro e a enumeração inicia do zero

### Requirement: Salvamento periódico e final
A ferramenta SHALL salvar o checkpoint periodicamente durante a enumeração e SHALL salvar um checkpoint final ao encerrar (normalmente ou por interrupção).

#### Scenario: Salvamento periódico
- **WHEN** a enumeração está em execução com checkpoint configurado
- **THEN** o progresso é salvo periodicamente

#### Scenario: Salvamento final por interrupção
- **WHEN** a enumeração é interrompida por sinal com checkpoint configurado
- **THEN** um checkpoint final é salvo antes do encerramento

### Requirement: Retomada
A ferramenta SHALL retomar a enumeração a partir de um checkpoint válido, restaurando a posição da geração e os IPs wildcard, sem repetir combinações já processadas.

#### Scenario: Retomada com checkpoint válido
- **WHEN** a enumeração inicia com um checkpoint válido
- **THEN** a geração continua da posição salva e o padrão wildcard é restaurado
