# PermiScan

Auditoria de controle de acesso, autorização e exposição de dados em bancos de dados,
plataformas BaaS e infraestrutura em nuvem.

O princípio do projeto: **verificar se os mecanismos de autorização realmente impedem
acessos indevidos**, e não apenas se um recurso de segurança está ligado. Uma tabela sem
policies não é automaticamente vulnerável; uma policy `USING (true)` não importa se nenhum
papel exposto tem privilégio sobre a tabela. Toda regra do PermiScan cruza a configuração
com os **privilégios efetivos** dos papéis que a aplicação expõe.

> **Uso autorizado apenas.** O PermiScan só se conecta a alvos declarados em um arquivo de
> escopo. Use-o em sistemas que são seus ou que você tem autorização expressa para avaliar.
> Veja [SECURITY.md](SECURITY.md).

## Status dos provedores

| Provedor | Status | O que existe hoje |
|---|---|---|
| Supabase | Análise estática disponível | RLS, policies, privilégios efetivos de `anon`/`authenticated`, views, views materializadas, funções `SECURITY DEFINER`. Validado contra o laboratório local que emula os papéis do Supabase; **ainda não validado contra um projeto Supabase real**. Storage e Auth: planejados. |
| PostgreSQL | Análise estática disponível | Mesmas regras, com papéis e schemas escolhidos pelo usuário, incluindo propriedade de tabela que anula o RLS. Validado em PostgreSQL 17. |
| Firebase | Planejado | Marco M6 em [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md). |
| Neon, MongoDB Atlas, Appwrite, PocketBase, AWS, GCP | Planejado | Prioridade 2. |
| Azure, Hasura, Directus, Cloudflare e outros | Planejado | Prioridade 3. |

Testes dinâmicos (validação com identidades sintéticas) ainda não existem: hoje todo
finding é de análise estática, com confiança no máximo `likely`.

## Instalação

Requer Python 3.12+ e [uv](https://docs.astral.sh/uv/).

```sh
uv sync
```

## Uso

1. Declare os alvos autorizados em `permiscan-scope.toml`:

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

2. Passe o DSN por variável de ambiente (credenciais nunca são aceitas como argumento):

   ```sh
   export PERMISCAN_DSN='postgresql://permiscan_auditor:SENHA@db.abcdefghij.supabase.co:5432/postgres?sslmode=require'
   ```

   Prefira um papel dedicado sem privilégios extras; veja [SECURITY.md](SECURITY.md#papel-de-auditoria-recomendado).

3. Valide a conexão e rode a análise:

   ```sh
   uv run permiscan check --provider supabase
   uv run permiscan scan  --provider supabase
   uv run permiscan scan  --provider supabase --format json --output findings.json --fail-on high
   uv run permiscan scan  --provider postgresql --role app_user --schema app
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
