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
| `-m, --maxlen` | Comprimento máximo de subdomínios | 5 |
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

- **Checkpoint/Resume**: Salva progresso automaticamente para retomar após interrupções
- **Cache de negativas**: Evita consultas redundantes NXDOMAIN
- **Generator otimizado**: Usa strings.Builder para O(n) ao invés de O(n²)
- **Buffer configurável**: Ajuste para sua rede
- **Graceful shutdown**: SIGINT/SIGTERM para encerramento limpo

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

- Go 1.22+
- Permissão para consultas DNS ao domínio alvo

## Aviso

Use apenas em domínios que você tem autorização para testar. Enumeração não autorizada pode ser ilegal.
