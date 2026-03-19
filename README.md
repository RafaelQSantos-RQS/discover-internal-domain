# discover-internal-domain

## Planejamento da Ferramenta de Descoberta de Ativos Internos via DNS (Go)

### 1. Visão geral
- **Objetivo:** Gerar combinações de subdomínios (a‑z, 0‑9) até um comprimento máximo e consultar o DNS interno, exibindo apenas resultados válidos.
- **Riscos principais:** DoS ao servidor DNS, falsos positivos por wildcard DNS e consumo excessivo de memória/CPU.
- **Mitigações:** Worker‑pool para limitar concorrência, `context.Context` com timeout por consulta, detecção e filtragem de wildcard, geração **iterativa** de combinações para evitar alocação massiva.

### 2. Algoritmo de Permutação
- Alfabeto: `abcdefghijklmnopqrstuvwxyz0123456789` (36 símbolos).
- Geração **iterativa** usando um vetor de índices que age como contador em base‑36; mantém apenas `O(maxLen)` memória.
- Uma goroutine de *generator* produz strings on‑the‑fly e as envia por um canal `jobs`.

### 3. Modelo de Concurrency – Worker Pool
- Canal `jobs` (buffer pequeno) alimenta **N workers** (configurável via flag `-workers`).
- Cada worker consome do canal, faz a consulta DNS e, se positivo, escreve a saída.
- `sync.WaitGroup` garante encerramento somente após todos os workers completarem.

### 4. Tratamento de DNS Wildcard
1. **Detecção preliminar** – consulta um nome aleatório impossível; se houver resposta, há wildcard.
2. **Filtragem** – comparar resposta de cada sub‑domínio com o conjunto obtido na detecção; aceitar apenas se diferente ou houver registros adicionais.
3. **Delay opcional** entre requisições para reduzir carga.

### 5. Controle de Timeout
- Cada consulta recebe `context.WithTimeout(parent, timeout)`; timeout configurável via flag `-timeout` (ex.: `2s`).
- Falhas por timeout são descartadas silenciosamente.

### 6. Flags de Configuração
```
-domain           string   Domínio base (ex.: example.com.br) (obrigatório)
-maxlen, -m      int      Comprimento máximo das combinações (default 5)
-workers, -w     int      Número de goroutines workers (default NumCPU)
-timeout, -t     duration Timeout por consulta DNS (default 2s)
-wildcard, -W    bool     Habilitar verificação de wildcard (default true)
-out, -o         string   Arquivo opcional para gravação dos resultados
-buffer, -b      int      Tamanho do buffer do canal de jobs (default 100)
-checkpoint, -k  string   Arquivo de checkpoint para retomada (default "")
-cache-ttl, -l   duration TTL do cache de respostas negativas (default 5m, 0=desabilitado)
```

### 7. Saída
Formato de linha única:
```
subX.example.com.br -> 10.0.1.23
subY.example.com.br -> 10.0.2.45,10.0.2.46
```

### 8. Robustez
- `sync.WaitGroup` + fechamento do canal garantem término ordenado.
- Tratamento de sinais (`SIGINT`) para cancelamento gracioso.

### 9. Otimizações implementadas
- **Checkpoint**: gravação atômica (temp + rename) do estado em JSON para retomada após interrupções.
- **Cache de respostas negativas**: cache LRU thread-safe com TTL configurável para evitar consultas NXDOMAIN repetidas.
- **Otimização do generator**: `strings.Builder` com pré-alocação para O(n) ao invés de O(n²).
- **Buffer configurável**: tamanho do canal de jobs ajustável via flag `-buffer`.
- **Resolver customizado** (`net.Resolver{PreferGo:true}`) para ignorar cache do SO.

### 10. Resumo da Implementação
1. Ler flags e validar parâmetros.
2. (Opcional) Carregar checkpoint existente para retomada.
3. Detectar wildcard (consulta aleatória) se `-W` habilitado.
4. Iniciar cache de respostas negativas se `-l > 0`.
5. Iniciar canal `jobs` com tamanho `-b`, WaitGroup e workers.
6. Gerador iterativo com `strings.Builder` produz sub‑domínios e envia ao canal.
7. Cada worker resolve via `net.Resolver` com timeout, filtra wildcard e imprime resultados.
8. Salvar checkpoint periodicamente (a cada 1000 combinações) e ao completar.
9. Encerrar aguardando WaitGroup, fechar arquivos.

---

Com esse planejamento você pode seguir diretamente para a codificação em Go, garantindo segurança, eficiência e capacidade de retomada em caso de falhas.
