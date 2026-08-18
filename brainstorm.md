# Brainstorm — dnsbrute: UX + Performance

> Capturado em 2026-08-18 (modo explore). Ideias para deixar a ferramenta mais
> agradável para devs e mais rápida, inspiradas em Gobuster, Puredns, Amass,
> DNSRecon, Dnsenum, Subbrute e Massdns.

---

## Estado atual (o que temos)

```
┌──────────┐   ┌──────────────┐   ┌─────────────┐
│ Generator│──▶│ async_channel│──▶│  Workers    │
│ (odômetro)│  │  (bounded)   │   │ (tokio)     │
└──────────┘   └──────────────┘   └──────┬──────┘
                                         │ lookup_ip
                                  ┌──────▼──────┐
                                  │ hickory     │
                                  │ resolver    │
                                  └─────────────┘
```

**Já temos:** brute-force exaustivo (`[a-z0-9-]`, len 1..=maxlen), worker pool,
detecção de wildcard (1 probe), cache negativo, checkpoint/resume, saída
stdout/arquivo.

**Não temos:** wordlist, progresso, JSON, resolvers customizados, outros record
types, stealth, fontes passivas, permutação.

---

## A identidade da ferramenta

Cada ferramenta de referência otimiza **um eixo**:

| Ferramenta | Eixo otimizado |
|------------|----------------|
| Massdns | Velocidade bruta (pacotes UDP crus) |
| Puredns | Volume + filtragem sofisticada de wildcard |
| Subbrute | Stealth (rotação de resolvers públicos) |
| Amass | Cobertura (OSINT passivo + ativo + permutação) |
| Gobuster | UX + wordlist |
| DNSRecon/Dnsenum | Record types + extras (AXFR, reverso) |

**Combo único da nossa ferramenta:** geração exaustiva + checkpoint/resume +
filtro de wildcard. Nicho real: *assets internos têm nomes imprevisíveis*
(`db-01-prod`, `svc-payroll-2`) — wordlist falha, brute-force exaustivo com
resume é o certo. Massdns não tem resume, Gobuster não faz brute-force exaustivo.

**Princípio:** manter a identidade, roubar o que faz sentido de cada ferramenta.

---

## 💡 Ideias de UX (devs felizes)

| # | Ideia | Impacto | Esforço | Inspiração |
|---|-------|---------|---------|------------|
| 1 | **Modo wordlist** `-w arquivo.txt` — brute-force exaustivo é caro; wordlist é o modo real de uso | 🔥 Alto | Baixo | Gobuster |
| 2 | **Progresso ao vivo** — barra/estatísticas: qps, elapsed, found, total | 🔥 Alto | Baixo | Gobuster |
| 3 | **Saída JSON** (`--json`) — consumível por scripts/outras ferramentas | Alto | Baixo | Amass |
| 4 | **Resolvers customizados** `-r arquivo` — lista de DNS servers | Alto | Baixo | Puredns/Subbrute |
| 5 | **Modo quiet** `-q` — só resultados, para scripting | Médio | Trivial | Gobuster |
| 6 | **Record types** `--records A,AAAA,MX,TXT,CNAME` | Médio | Médio | DNSRecon |
| 7 | **Zone transfer** (AXFR) — tentativa barata, ganho enorme quando funciona | Médio | Trivial | DNSRecon/Dnsenum |
| 8 | **Reverse lookup** dos IPs encontrados | Médio | Médio | Dnsenum |
| 9 | **Modo permutação** — a partir de subdomínios conhecidos (Amass-style) | Alto | Médio | Amass |
| 10 | **Fontes passivas** (crt.sh / CT logs) | Alto | Médio | Amass |
| 11 | **Rate limit** `--rate` — stealth, não tomar block | Médio | Baixo | Subbrute |
| 12 | **Resumo melhor** — qps, breakdown por tipo | Baixo | Trivial | — |

---

## ⚡ Ideias de performance

| # | Ideia | Impacto | Esforço | Inspiração |
|---|-------|---------|---------|------------|
| P1 | **Raw UDP DNS** (pacotes crus, massdns-style) — bypass do resolver completo | 🔥 10-100x | Alto (reescrita) | Massdns |
| P2 | **Tunar o hickory** — `attempts: 1`, `cache_size: 0` (cache interno desligado), `use_hosts_file: false` | Médio | **Trivial** | — |
| P3 | **Pool de resolvers** com round-robin — evita rate limit de um só | Alto | Baixo | Subbrute |
| P4 | **Writer task** (channel em vez de `Mutex<Box<dyn Write>>`) — remove contenção de lock | Médio | Baixo | — |
| P5 | **Wildcard robusto** — N probes aleatórios em vez de 1 (Puredns faz filtragem bem mais sofisticada) | Médio | Baixo | Puredns |
| P6 | **Seguir CNAMEs** — wildcard via CNAME (CDN) é comum e hoje escapa | Médio | Médio | — |
| P7 | **Workers adaptativos** — auto-tune pela latência | Baixo | Médio | — |

---

## 🔍 Achado importante

**O cache negativo é inútil no modo brute-force puro.**

Cada combinação do odômetro é única — `neg_cache.is_cached()` **nunca acerta**.
O cache só paga quando há repetição de FQDN, o que só acontece com wordlist ou
permutação. Hoje ele adiciona um lock + hash lookup em **toda** query, para zero
benefício.

```
Brute-force puro:  a.example.com, b.example.com, c.example.com...  (todos únicos)
                   neg_cache.is_cached() → sempre miss → overhead puro

Com wordlist:      admin, admin, admin... (duplicatas reais) → cache paga
```

Ou seja: o cache negativo é **dívida no modo atual** e **ativo valioso no
futuro** (quando entrar wordlist/permutação). Reforça que wordlist é a feature
nº 1 — ela ativa o valor do cache que já existe.

---

## Priorização sugerida

**Fase 1 — "devs felizes" (baixo esforço, alto impacto):**
1. Wordlist `-w` (ativa o cache negativo que já existe!)
2. Progresso ao vivo
3. Resolvers customizados `-r` + tunar hickory (P2, trivial)
4. JSON + `-q`

**Fase 2 — "mais rápido":**
5. Writer task (P4)
6. Wildcard robusto (P5)
7. Pool de resolvers (P3)

**Fase 3 — "ambicioso":**
8. Raw UDP (P1) — só se a velocidade virar o gargalo real
9. Permutação + fontes passivas (mudam o escopo da ferramenta)

---

## Threads abertas

1. **Confirma a identidade?** Leitura atual: "brute-force exaustivo, rápido e
   retomável para assets internos". Se o ideal for outro (ex.: virar um "Amass
   de assets internos" com passivo+permutação), o roadmap muda bastante.
2. **Wordlist é bem-vinda?** Ela muda o caráter da ferramenta (de "exaustivo"
   para "híbrido"). Ou manter 100% brute-force?
3. **Raw UDP (massdns-style) atrai?** É a maior reescrita, mas é o salto de
   performance real. Ou o hickory tunado já basta?
4. **Stealth importa?** (resolvers rotativos, rate limit) — ou é ferramenta de
   rede interna onde isso não é problema?