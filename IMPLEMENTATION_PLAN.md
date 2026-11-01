# Plano de implementação

Marcos pequenos e verificáveis. Cada marco só fecha com testes cobrindo cenários
vulneráveis **e** seguros, executados contra infraestrutura real quando ela existir no
laboratório.

## M0 — Fundação e análise estática PostgreSQL/Supabase ✅

- [x] Modelo comum de findings (`permiscan/findings.py`) com fingerprint para deduplicação.
- [x] Escopo autorizado: allowlist em TOML, DSN fixado ao alvo validado (`permiscan/scope.py`).
- [x] Contrato de adaptadores com capacidades declaradas (`permiscan/adapters/base.py`).
- [x] Coleta somente leitura do catálogo PostgreSQL em snapshot imutável.
- [x] Privilégios efetivos (herança, `PUBLIC`, colunas, `USAGE` de schema).
- [x] 9 regras estáticas (RLS, policies, propriedade, views, funções, atributos de papel).
- [x] Adaptador Supabase (papéis do PostgREST) e PostgreSQL (papéis escolhidos).
- [x] CLI `check`/`scan`, saída texto/JSON, `--fail-on` para CI.
- [x] Laboratório Docker com papéis do Supabase e cenários vulneráveis/seguros.
- [x] Testes unitários das regras e do escopo; integração com o laboratório; CI.

## M1 — API e persistência

FastAPI + Pydantic + SQLAlchemy 2 + Alembic, banco da aplicação em PostgreSQL.

- Modelo de dados: Organization, User, Project, ProviderConnection, Scan, ScanTarget,
  TestCase, TestExecution, Finding, Evidence, Remediation, ScanBaseline, AuditLog.
- Credenciais cifradas em repouso (AES-GCM, chave fora do banco); nunca retornadas pela API.
- Escopo persistido por projeto; toda execução valida o escopo no servidor.
- Execução de scans em worker com timeout, limite de concorrência e cancelamento.
- IDs sequenciais `PS-AAAA-NNNN` atribuídos na persistência; fingerprint para deduplicação.
- AuditLog de criação de conexões, execuções e exportações.
- `docker compose up` sobe API + banco da aplicação + laboratório.

**Aceite:** criar projeto, registrar conexão Supabase, validar conexão, executar scan e
consultar findings persistidos, tudo via API e contra o laboratório.

## M2 — Dashboard

Next.js + TypeScript + Tailwind + shadcn/ui, consumindo apenas a API do M1.

- Projetos, conexões (status e capacidades), configuração de auditoria com confirmação de
  escopo, resultados com filtros, detalhe do finding com evidências e remediação.

**Aceite:** fluxo completo pelo navegador contra o laboratório, sem dados fictícios.

## M3 — Relatórios

- JSON (já disponível na CLI), HTML, PDF; sumário executivo e relatório técnico.
- Comparação histórica com `ScanBaseline` usando fingerprints.

## M4 — Supabase além do catálogo

- Storage: buckets públicos e policies de `storage.objects`.
- Auth: descoberta de contextos de autenticação e claims usados nas policies.
- Schemas realmente expostos pela Data API.
- Auditoria externa: só com a URL do projeto e a chave publishable/anon (públicas por
  design), ler o OpenAPI do PostgREST (`GET /rest/v1/`) para listar as tabelas, colunas e
  RPCs que a Data API realmente expõe, e cruzar isso com o snapshot do catálogo quando
  houver credencial de banco.
- Chaves secretas no cliente: detectar `service_role` (JWT com `role=service_role`) e
  `sb_secret_…` em bundles de frontend e no código-fonte (critical).
- Validação contra um projeto Supabase real (de teste) antes de declarar suporte completo.

## M5 — Motor dinâmico e diferencial (PostgreSQL/Supabase)

- Identidades sintéticas (anon, usuário A, usuário B, organização X/Y).
- Cada teste roda em transação com `SET LOCAL ROLE` + `request.jwt.claims` e termina em
  `ROLLBACK`; escrita apenas sobre registros sintéticos criados pelo próprio teste.
- Comparação esperado × observado entre identidades; findings confirmados passam a
  `confidence = confirmed`.
- Exige modo `dynamic` explicitamente autorizado no escopo.
- Prova mínima: contar em vez de ler (`SELECT count(*)` ou `Prefer: count=exact` na Data
  API). Nenhuma linha real é guardada como evidência.
- RPCs nunca são executadas às cegas. Só são chamadas funções `STABLE`/`IMMUTABLE` (o
  `provolatile` do catálogo) ou funções que o usuário marcar explicitamente.

## M6 — Firebase

- Parser das Security Rules (Firestore, Storage, Realtime Database) e regras estáticas.
- Testes dinâmicos reproduzíveis com Firebase Emulator Suite e dados sintéticos.
- Aqui nasce o motor estático genérico: com dois provedores reais, o que for comum sai dos
  adaptadores para `engines/`.

## M7 — Motor de risco

- CVSS quando aplicável, correlação entre findings (ex.: view definer sobre tabela sem RLS),
  priorização e redução de falsos positivos.
- Sensibilidade pelos nomes das colunas no catálogo (`senha`, `token`, `cpf`, `email`,
  `telefone`…) para elevar a severidade de uma exposição sem ler nenhum dado.

## Referência: extensão "Supabase RLS Security Scanner"

Ela faz uma varredura caixa-preta: acha a URL e a chave anon na página e consulta a Data API.
O PermiScan aproveita a descoberta pelo OpenAPI, a detecção de `service_role` no cliente e a
classificação de colunas sensíveis. Não copia o que contraria a seção 10 do plano: ler até
100 linhas e guardá-las, testar escrita com `POST {}` em cada tabela, chamar todas as RPCs
com `{}` (inclusive as de nome `delete`/`admin`), varrer qualquer site sem escopo e concluir
"RLS desabilitado" só porque vieram linhas, já que uma policy pública intencional produz o
mesmo resultado.

## M8+ — Prioridade 2

Neon (reuso do adaptador PostgreSQL + branches), PocketBase, Appwrite, MongoDB Atlas, AWS, GCP.

## Critérios de aceitação do MVP

| Critério | Situação |
|---|---|
| Aplicação inicia via Docker Compose | Parcial: laboratório sim; API/dashboard em M1/M2 |
| Dashboard comunica com o backend | M2 |
| Criação de projetos | M1 |
| Registro de provedores | Registro interno pronto; via API em M1 |
| Validação de conexão Supabase | ✅ `permiscan check --provider supabase` (laboratório) |
| Descoberta de metadados PostgreSQL | ✅ |
| Análise de configurações RLS | ✅ |
| Policies inseguras conhecidas identificadas | ✅ |
| Privilégios SQL analisados | ✅ privilégios efetivos |
| Findings normalizados e persistidos | Normalizados ✅; persistência em M1 |
| Findings com evidências e recomendações | ✅ |
| Relatórios exportáveis | JSON ✅; HTML/PDF em M3 |
| Testes cobrem cenários vulneráveis e seguros | ✅ |
| Firebase com implementação inicial ou marco delimitado | Marco M6 delimitado |
| Nenhuma credencial exposta nos logs | ✅ testado (erros redigidos, DSN só por ambiente) |
| Documentação de instalação e uso autorizado | ✅ |
