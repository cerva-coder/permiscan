# Arquitetura

## Fluxo atual

```
CLI ──► scope.parse_dsn ──► scope.authorize ──► Adapter.check ──► Adapter.scan
             │                    │                                   │
     rejeita DSN ambíguo   allowlist TOML               catalog.collect (1 transação READ ONLY)
                                                                     │
                                                              Snapshot imutável
                                                                     │
                                                         rules.analyze (funções puras)
                                                                     │
                                                       list[Finding] ──► texto / JSON
```

O alvo é sempre explícito no comando. A allowlist (`--scope`) é opcional e, quando passada,
roda entre `parse_dsn` e `check`. Há dois outros pontos de entrada, com o mesmo formato de
finding e a mesma saída:

- `scan-api` → `SupabaseApiScanner` (URL + chave anon): lê o OpenAPI do PostgREST, descobre
  tabelas/RPCs e observa, como anônimo, o que cada tabela retorna. Leitura por padrão; escrita
  e chamada de RPC sob flag (`--probe-writes`, `--probe-rpc`), com RPCs destrutivas protegidas.
- `detect` → `detect_instances` sobre uma página (`--url`) ou arquivo (`--file`): extrai URL e
  chaves Supabase; com `--scan`, roda o `SupabaseApiScanner` em cada instância encontrada.
- `scan-rules` → `FirebaseAdapter` (arquivo local): análise textual das Security Rules.

## Componentes

| Caminho | Responsabilidade |
|---|---|
| `permiscan/findings.py` | Formato comum de findings: severidade, confiança, categoria, CWE/OWASP, evidência, remediação, fingerprint. |
| `permiscan/scope.py` | Parse do DSN, allowlist de alvos, fixação do alvo na conexão, redação de segredos. |
| `permiscan/adapters/base.py` | Contrato `Adapter`: `provider`, `capabilities`, `check()`, `scan()`. |
| `permiscan/adapters/postgres/catalog.py` | Consultas ao catálogo e montagem do `Snapshot`. |
| `permiscan/adapters/postgres/rules.py` | Regras estáticas sobre o `Snapshot`. |
| `permiscan/adapters/postgres/__init__.py` | `PostgresAdapter`: sessão somente leitura, `check`, `scan`. |
| `permiscan/adapters/supabase.py` | `SupabaseAdapter`: PostgreSQL com os papéis e schemas da Data API. |
| `permiscan/adapters/supabase_api.py` | `SupabaseApiScanner`: varredura externa (caixa-preta) pela Data API com URL + chave anon. |
| `permiscan/adapters/firebase.py` | `FirebaseAdapter`: análise estática de Security Rules (Firestore/Storage/RTDB). |
| `permiscan/sensitivity.py` | Classificação de sensibilidade pelo nome da coluna/campo. |
| `permiscan/cli.py` | Interface de linha de comando (`check`, `scan`, `scan-api`, `scan-rules`). |
| `tests/fixtures/lab` | Laboratório: papéis do Supabase, cenários vulneráveis e seguros. |

## Decisões

**Snapshot + regras puras.** A coleta é separada da análise. As regras recebem um
`Snapshot` imutável e devolvem findings, sem tocar a rede. Isso permite testar cada regra
com snapshots sintéticos e reaproveitar as mesmas regras em qualquer provedor baseado em
PostgreSQL (Supabase, Neon, RDS, Cloud SQL).

**Privilégios efetivos, não GRANTs literais.** Os privilégios vêm de
`has_any_column_privilege`, `has_table_privilege`, `has_function_privilege`,
`has_schema_privilege` e `pg_has_role`, chamados para cada papel auditado. Isso resolve
herança de papéis, concessões a `PUBLIC`, privilégios por coluna e falta de `USAGE` no
schema. É o que permite dizer "esta tabela sem RLS não é alcançável" em vez de reportar
toda tabela sem policy.

**Uma transação READ ONLY por sessão.** `conn.read_only = True` faz o psycopg abrir
`BEGIN READ ONLY`; `SET LOCAL statement_timeout` vale até o fim da transação. As duas
coisas funcionam por trás de poolers em modo transação, onde `SET` de sessão e o parâmetro
`options` não são confiáveis. A transação termina em `ROLLBACK`.

**Alvo fixado.** O DSN precisa declarar `host` e `dbname`. Na conexão, `host`, `port` e
`dbname` são passados explicitamente e sobrepõem `PGHOST`/`PGPORT`/`PGDATABASE`.
`hostaddr`, `service` e múltiplos hosts são recusados, porque fariam a libpq conectar a
um endereço diferente do validado. Em poolers compartilhados o escopo pode fixar o usuário,
que identifica o projeto.

**Supabase é PostgreSQL + PostgREST.** O adaptador Supabase herda o PostgreSQL e audita os
papéis que o PostgREST assume (`anon`, `authenticated`) no schema exposto (`public`). A
ausência desses papéis faz o `check` falhar: o alvo não é um projeto Supabase.

**Confiança honesta.** Análise estática nunca emite `confirmed`; esse nível fica reservado
a comportamento observado em teste dinâmico (M5). Heurísticas textuais saem como `possible`.

**Fingerprint estável.** `sha256(provider|rule_id|resource)` identifica o mesmo problema
entre execuções, base para deduplicação, baseline e reteste.

## Estrutura do repositório em relação ao plano

O plano propõe um monorepo com `apps/`, `core/`, `engines/`, `adapters/` e `rules/`.
Diretórios só são criados quando há código real para eles; não existem adaptadores vazios.

| Plano | Hoje | Quando muda |
|---|---|---|
| `core/scope` | `permiscan/scope.py` | — |
| `adapters/base`, `adapters/supabase`, `adapters/postgresql` | `permiscan/adapters/` | — |
| `engines/static_analysis`, `rules/` | `permiscan/adapters/postgres/rules.py` | M6: com Firebase, o que for comum vira motor genérico em `permiscan/engines/` |
| `apps/cli` | `permiscan/cli.py` | — |
| `apps/api`, `core/orchestrator`, `core/scheduler` | — | M1, em `permiscan/api/` |
| `apps/dashboard` | — | M2, em `apps/dashboard/` (Node) |
| `engines/dynamic_analysis`, `engines/differential_testing` | — | M5 |
| `engines/risk_scoring` | ordenação por severidade em `rules.analyze` | M7 |
| `reporting/` | JSON na CLI | M3 |

Regras específicas de um provedor ficam junto do adaptador porque dependem do formato do
catálogo dele. Um motor genérico extraído com um único provedor seria uma abstração
adivinhada; com dois provedores reais (PostgreSQL e Firebase) o formato comum aparece.

## Contrato do adaptador

```python
class Adapter(ABC):
    provider: ClassVar[str]
    capabilities: ClassVar[frozenset[Capability]]  # apenas o que está implementado
    def check(self) -> dict: ...                     # valida conexão e detecta o alvo
    def scan(self) -> list[Finding]: ...
```

Capacidades atuais: `metadata`, `rls_analysis`, `privilege_analysis`, `function_analysis`,
`view_analysis`. Novas capacidades entram no enum quando houver implementação.

## Limitações conhecidas

- A detecção de restrição de propriedade em policies é textual (`auth.uid()`,
  `auth.jwt()`, `current_user`, `session_user`, `current_setting(`). Funções auxiliares
  como `is_member(org_id)` geram falso positivo, por isso esses findings saem como `possible`.
- `pg-view-definer` não resolve as tabelas subjacentes da view; reporta toda view legível
  sem `security_invoker`. `security_invoker` exige PostgreSQL 15+.
- Atributos `BYPASSRLS`/`SUPERUSER` só são verificados nos papéis auditados, não em papéis
  que eles possam assumir com `SET ROLE`.
- Supabase Storage, Auth e a configuração real de schemas expostos ainda não são analisados (M4).
- A varredura pela Data API (`scan-api`) é a única fonte dinâmica hoje; a validação dinâmica
  do banco por conexão direta, com identidades sintéticas, ainda não existe (M5).
- `scan-api` conclui "legível por anônimo" a partir do comportamento observado, mas não
  distingue dado público intencional de exposição indevida: por isso a descrição pede
  confirmação da intenção, e a severidade vem da sensibilidade dos nomes das colunas.
- A análise de Firebase Rules é textual: cobre `if true`, `".read"/".write": true` e escrita
  com apenas `request.auth != null`. Não interpreta funções auxiliares (`function …`), `get()`
  nem a hierarquia de `match`; validação de comportamento fica para o Emulator (M6).
