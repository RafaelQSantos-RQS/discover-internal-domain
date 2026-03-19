# dnsbrute

Ferramenta de enumeração DNS para descoberta de ativos internos via brute-force de subdomínios.

## Instalação

```bash
# Compilar
go build -o dnsbrute .

# Ou instalar via go install
go install .
```

## Uso

```bash
# Enumeração básica
./dnsbrute -d example.com -m 3 -w 20

# Com checkpoint para retomar após interrupção
./dnsbrute -d example.com -m 4 -k checkpoint.json

# Com cache de respostas negativas
./dnsbrute -d example.com -l 10m -c 100000

# Aumentar buffer para melhor throughput
./dnsbrute -d example.com -b 500 -w 50
```

## Opções

| Flag | Descrição | Padrão |
|------|-----------|--------|
| `-d, --domain` | Domínio base (obrigatório) | - |
| `-m, --maxlen` | Comprimento máximo (max 63, limite DNS) | 5 |
| `-w, --workers` | Número de workers concorrentes | NumCPU |
| `-t, --timeout` | Timeout por consulta DNS | 2s |
| `-W, --wildcard` | Habilitar detecção de wildcard | true |
| `-o, --out` | Arquivo de saída | stdout |
| `-c, --max-combinations` | Limite de combinações | unlimited |
| `-b, --buffer` | Tamanho do buffer de jobs | 100 |
| `-k, --checkpoint` | Arquivo de checkpoint | - |
| `-l, --cache-ttl` | TTL do cache negativo | 5m |

## Como funciona

1. Gera combinações iterativas de subdomínios (a-z, 0-9, `-`)
2. Workers concurrentes consultam o DNS
3. Wildcards são detectados e filtrados automaticamente
4. Resultados válidos são exibidos

## Saída

```
subdominio.example.com -> 192.168.1.10
outro.example.com -> 10.0.0.5,10.0.0.6
```

## Features

- **TUI Interativa**: Interface visual com barra de progresso, lista de descobertas em tempo real, e estatísticas
- **CLI Mode**: Modo texto para CI/scripting (use `--no-tui`)
- **Checkpoint atômico**: Salva progresso com escrita segura (temp + rename + sync) para retomar após interrupções
- **Cache de negativas com limite**: Evita consultas NXDOMAIN redundantes com LRU (max 100k entradas)
- **Segurança de memória**: maxlen limitado a 63 (label DNS), strings.Builder com grow validado
- **Thread-safe**: Contador atômico para tracking de progresso
- **Graceful shutdown**: SIGINT/SIGTERM para encerramento limpo

### Exemplo TUI

```
┌─────────────────────────────────────────────────────────┐
│  🔍 dnsbrute - Enumerating example.com                   │
├─────────────────────────────────────────────────────────┤
│  Progress: ████████████░░░░░░░░ 45% (450/1000)          │
│  Speed: 25 req/s | Workers: 50 | Elapsed: 18s            │
├─────────────────────────────────────────────────────────┤
│  ✓ www.example.com → 192.168.1.10                       │
│  ✓ api.example.com → 10.0.0.5, 10.0.0.6                │
│  ✓ mail.example.com → 172.16.0.1                       │
├─────────────────────────────────────────────────────────┤
│  Press Ctrl+C to stop                                   │
└─────────────────────────────────────────────────────────┘
```

### Modo CLI (para CI/scripting)

```bash
./dnsbrute -d example.com -m 4 -w 50 --no-tui
```

## Construção Cruzada

```bash
# Linux
GOOS=linux GOARCH=amd64 go build -o dnsbrute-linux-amd64 .

# macOS
GOOS=darwin GOARCH=arm64 go build -o dnsbrute-darwin-arm64 .

# Windows
GOOS=windows GOARCH=amd64 go build -o dnsbrute.exe .
```

## Requisitos

- Go 1.26+
- Permissão para consultas DNS ao domínio alvo

## Aviso

Use apenas em domínios que você tem autorização para testar. Enumeração não autorizada pode ser ilegal.
