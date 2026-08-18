# dnsbrute

Ferramenta de enumeração DNS para descoberta de ativos internos via brute-force de subdomínios. Escrita em Rust.

## Instalação

```bash
# Compilar
cargo build --release

# Binário em target/release/dnsbrute
```

## Uso

```bash
# Enumeração básica
cargo run -- -d example.com -m 3 -w 20

# Com checkpoint para retomar após interrupção
cargo run -- -d example.com -m 4 -k checkpoint.json

# Com cache de respostas negativas
cargo run -- -d example.com -l 10m -c 100000

# Aumentar buffer para melhor throughput
cargo run -- -d example.com -b 500 -w 50

# Salvar resultados em arquivo
cargo run -- -d example.com -m 3 -o resultados.txt
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

Durações usam sufixos `s`, `m`, `h` (ex.: `2s`, `5m`, `1h`).

## Como funciona

1. Gera combinações iterativas de subdomínios (a-z, 0-9, `-`)
2. Workers concorrentes (tokio) consultam o DNS
3. Wildcards são detectados e filtrados automaticamente
4. Resultados válidos são exibidos

## Saída

```
subdominio.example.com -> 192.168.1.10
outro.example.com -> 10.0.0.5, 10.0.0.6
```

O resumo final (total verificado, encontrado, tempo) é exibido em stderr, permitindo uso em pipelines.

## Features

- **CLI**: Interface declarativa com clap (flags novas, sem compatibilidade com a versão Go)
- **Worker pool**: Concorrência via tokio com canal de jobs com buffer limitado
- **Checkpoint atômico**: Salva progresso com escrita segura (temp + rename + sync, permissões 0600) para retomar após interrupções
- **Cache de negativas com limite**: Evita consultas NXDOMAIN redundantes com evicção FIFO (max 100k entradas) e TTL
- **Segurança de memória**: maxlen limitado a 63 (label DNS)
- **Graceful shutdown**: SIGINT/SIGTERM com salvamento final de checkpoint

## Construção Cruzada

```bash
# Linux
cargo build --release --target x86_64-unknown-linux-gnu

# macOS
cargo build --release --target aarch64-apple-darwin

# Windows
cargo build --release --target x86_64-pc-windows-msvc
```

## Requisitos

- Rust 1.75+ (edition 2021)
- Permissão para consultas DNS ao domínio alvo

## Aviso

Use apenas em domínios que você tem autorização para testar. Enumeração não autorizada pode ser ilegal.
