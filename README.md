# PermiScan

Auditoria de controle de acesso, autorização e exposição de dados em bancos de dados,
plataformas BaaS e infraestrutura em nuvem.

O princípio do projeto: **verificar se os mecanismos de autorização realmente impedem
acessos indevidos**, e não apenas se um recurso de segurança está ligado. Uma tabela sem
policies não é automaticamente vulnerável; uma policy `USING (true)` não importa se nenhum
papel exposto tem privilégio sobre a tabela. Toda regra do PermiScan cruza a configuração
com os **privilégios efetivos** dos papéis que a aplicação expõe.

> **Uso autorizado apenas.** Cada comando recebe o alvo explicitamente (o DSN, a URL do
> projeto ou o arquivo de regras que você indica). Use-o em sistemas que são seus ou que
> você tem autorização expressa para avaliar. Veja [SECURITY.md](SECURITY.md).

## Status dos provedores

| Provedor | Status | O que existe hoje |
|---|---|---|
| Supabase (banco) | Análise estática disponível | RLS, policies, privilégios efetivos de `anon`/`authenticated`, views, views materializadas, funções `SECURITY DEFINER`. Validado contra o laboratório local que emula os papéis do Supabase; **ainda não validado contra um projeto Supabase real**. |
| Supabase (Data API) | Testes dinâmicos disponíveis | Varredura externa com URL + chave anon: descobre tabelas/RPCs pelo OpenAPI, observa leitura anônima e, sob flag, testa escrita e chamada de RPC. Detecta chave `service_role` no cliente e extrai credenciais de uma página/bundle (`detect`). |
| PostgreSQL | Análise estática disponível | Mesmas regras do banco, com papéis e schemas escolhidos pelo usuário, incluindo propriedade de tabela que anula o RLS. Validado em PostgreSQL 17. |
| Firebase | Análise estática disponível | Security Rules de Firestore, Storage e Realtime Database. Testes dinâmicos com o Emulator: planejados (M6). |
| Neon, MongoDB Atlas, Appwrite, PocketBase, AWS, GCP | Planejado | Prioridade 2. |
| Azure, Hasura, Directus, Cloudflare e outros | Planejado | Prioridade 3. |

A varredura pela Data API observa comportamento real (confiança `confirmed`); a análise de
catálogo e de regras é estática (confiança no máximo `likely`). A validação dinâmica do
banco com identidades sintéticas ainda não existe (M5).

## Instalação

Requer Python 3.12+ e [uv](https://docs.astral.sh/uv/).

```sh
uv sync
```

## Uso

### Menu interativo (sem argumentos)

Rode `permiscan` sem nada e ele pergunta o que fazer, pedindo cada dado na hora:

```sh
uv run permiscan
```

```
=== PermiScan ===
O que você quer fazer?
  1) Reconhecimento automático (só uma URL)
  2) Varredura externa Supabase (Data API)
  3) Detectar credenciais numa página ou arquivo
  4) Analisar banco PostgreSQL/Supabase (via DSN)
  5) Analisar Firebase Security Rules (arquivo)
  0) Sair
```

O DSN do banco é pedido sem aparecer na tela. Os testes que alteram o alvo (escrita/RPC) são
perguntados com "não" como padrão. Os comandos por argumento abaixo continuam disponíveis para
scripts e CI.

### Reconhecimento automático (só com a URL)

Identifica a stack, descobre endpoints e credenciais expostas e roteia para as análises
cabíveis — sem você dizer o provedor:

```sh
uv run permiscan recon https://app.exemplo.com
uv run permiscan recon https://app.exemplo.com --probe-writes --probe-rpc   # Supabase: testes ativos
uv run permiscan recon https://app.exemplo.com --format json
```

O relatório unificado traz: stack identificada (com confiança), endpoints descobertos,
configurações/chaves expostas, findings dos adaptadores (RLS, policies, RTDB…) e
recomendações. O que exige credencial adicional (DSN do banco, arquivo de regras do Firebase)
é apontado nas recomendações, não assumido.

### Análise do banco (Supabase/PostgreSQL via conexão direta)

O DSN vai por variável de ambiente (credenciais nunca são aceitas como argumento). Prefira
um papel dedicado sem privilégios extras; veja [SECURITY.md](SECURITY.md#papel-de-auditoria-recomendado).

```sh
export PERMISCAN_DSN='postgresql://permiscan_auditor:SENHA@db.abcdefghij.supabase.co:5432/postgres?sslmode=require'

uv run permiscan check --provider supabase
uv run permiscan scan  --provider supabase
uv run permiscan scan  --provider supabase --format json --output findings.json --fail-on high
uv run permiscan scan  --provider postgresql --role app_user --schema app
```

Opcionalmente, restrinja os alvos a uma allowlist com `--scope arquivo.toml`:

```toml
[[targets]]
host = "db.abcdefghij.supabase.co"
port = 5432
database = "postgres"

# Em poolers compartilhados, fixe também o usuário: o host atende vários projetos.
[[targets]]
host = "aws-0-sa-east-1.pooler.supabase.com"
port = 5432
database = "postgres"
user = "permiscan_auditor.abcdefghij"
```

### Varredura externa pela Data API do Supabase

Só com a URL do projeto e a chave anon (ambas públicas, embarcadas em qualquer frontend).
Por padrão observa só o que uma requisição anônima **lê**. Os testes que alteram o alvo são
flags explícitas e devem ser usados apenas onde você tem autorização.

```sh
export PERMISCAN_ANON_KEY='eyJhbGci...'   # chave anon/publishable

# leitura (padrão): tabelas legíveis por anônimo + detecção de chave service_role
uv run permiscan scan-api --url https://abcdefghij.supabase.co

# amostra maior de linhas como evidência
uv run permiscan scan-api --url https://abcdefghij.supabase.co --rows 20

# testes ativos (alteram o alvo): escrita e chamada de RPC
uv run permiscan scan-api --url https://abcdefghij.supabase.co --probe-writes --probe-rpc

# também chama RPCs de nome destrutivo (delete/drop/admin/…) — só em projeto próprio/de teste
uv run permiscan scan-api --url https://abcdefghij.supabase.co --probe-rpc --include-destructive
```

| Flag | O que faz | Altera o alvo? |
|---|---|---|
| (padrão) | lê 1 linha por tabela; detecta `service_role` | não |
| `--rows N` | lê até N linhas como amostra | não |
| `--probe-writes` | `POST` para testar escrita anônima | pode inserir linha |
| `--probe-rpc` | chama RPCs para ver se respondem sem auth | executa a função |
| `--include-destructive` | inclui RPCs de nome destrutivo em `--probe-rpc` | executa a função |

### Detecção de credenciais em uma página ou bundle

Como a auto-detecção da extensão, mas em um alvo que você indica (uma página ou um arquivo
local), não varrendo a web. Extrai URLs de projeto e chaves (anon, `service_role`,
`sb_publishable_`, `sb_secret_`). Com `--scan`, varre cada instância encontrada:

```sh
uv run permiscan detect --url https://app.exemplo.com
uv run permiscan detect --file dist/bundle.js
uv run permiscan detect --url https://app.exemplo.com --scan --probe-writes
```

### Firebase Security Rules

Análise estática de um arquivo de regras local (o serviço é detectado pelo nome do arquivo):

```sh
uv run permiscan scan-rules --rules firestore.rules
uv run permiscan scan-rules --rules storage.rules
uv run permiscan scan-rules --rules database.rules --service rtdb
```

| Código de saída | Significado |
|---|---|
| 0 | Sucesso |
| 1 | Erro de conexão ou configuração |
| 2 | Alvo fora do escopo autorizado |
| 3 | Há finding com severidade igual ou maior que `--fail-on` |

A sessão com o banco é uma única transação `READ ONLY` com `statement_timeout`. O PermiScan
lê apenas o catálogo do sistema; nenhuma linha das suas tabelas é consultada.

## Regras disponíveis

| Regra | Detecta | Severidade |
|---|---|---|
| `pg-rls-disabled` | Tabela sem RLS com privilégios efetivos para papéis expostos (inclui policies ignoradas) | critical (escrita) / high (leitura) |
| `pg-policy-unrestricted` | Policy com condição sempre verdadeira, aplicável a papel com o privilégio correspondente | high (escrita) / medium (leitura) |
| `pg-policy-no-ownership` | Policy de escrita que não referencia a identidade da requisição | medium |
| `pg-rls-owner-bypass` | Papel auditado é dono da tabela e o RLS não está forçado | high |
| `pg-role-bypass-rls` | Papel auditado com `SUPERUSER` ou `BYPASSRLS` | critical |
| `pg-view-definer` | View sem `security_invoker` legível por papéis expostos | medium |
| `pg-matview-exposed` | View materializada (sem suporte a RLS) legível por papéis expostos | medium |
| `pg-func-secdef-exposed` | Função `SECURITY DEFINER` executável por papéis expostos | medium |
| `pg-func-search-path` | Função `SECURITY DEFINER` sem `search_path` fixo | medium |
| `supabase-api-anon-read` | Tabela que retorna dados a uma requisição anônima na Data API | medium–critical (pela sensibilidade das colunas) |
| `supabase-api-anon-write` | Tabela em que o anônimo consegue escrever (`--probe-writes`) | high–critical |
| `supabase-api-anon-rpc` | Função RPC que responde sem autenticação (`--probe-rpc`) | pelo nome da função |
| `supabase-api-rpc-exposed` | RPC de nome destrutivo exposta, não chamada sem `--include-destructive` | info |
| `supabase-service-role-key` | Chave `service_role` (ignora RLS) usada no cliente | critical |
| `exposed-aws-access-key` | AWS Access Key ID (`AKIA…`) embarcada no frontend | critical |
| `exposed-sensitive-file` | Arquivo sensível (`.env`, `.git/config`) servido publicamente | critical |
| `firebase-rule-public` | Regra `allow …: if true` (Firestore/Storage) | high (leitura) / critical (escrita) |
| `firebase-rule-any-authenticated-write` | Escrita exigindo só `request.auth != null`, sem propriedade | medium |
| `firebase-rtdb-public-read` / `-write` | Realtime Database com `".read"`/`".write": true` | high / critical |

## Laboratório local

Um PostgreSQL intencionalmente vulnerável, com cenários vulneráveis e seguros lado a lado
([tests/fixtures/lab](tests/fixtures/lab)):

```sh
docker compose up -d --wait lab-db
export PERMISCAN_DSN=postgresql://permiscan_auditor:auditor-lab-only@127.0.0.1:55432/permiscan_lab
uv run permiscan scan --provider supabase --scope tests/fixtures/lab/scope.toml
```

## Documentação

- [ARCHITECTURE.md](ARCHITECTURE.md): componentes, decisões e limitações conhecidas.
- [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md): marcos e critérios de aceitação.
- [SECURITY.md](SECURITY.md): uso autorizado, postura de segurança e relato de vulnerabilidades.
- [CONTRIBUTING.md](CONTRIBUTING.md): ambiente de desenvolvimento, testes e como adicionar regras.
