# Segurança

## Uso autorizado

O PermiScan é uma ferramenta de segurança defensiva. Use-a somente em sistemas que são
seus ou que você tem autorização expressa e documentada para avaliar: suas aplicações,
avaliações contratadas, ambientes de laboratório e aplicações intencionalmente vulneráveis.

A ferramenta reforça isso tecnicamente de duas formas: cada comando recebe o alvo
explicitamente (o DSN, a URL ou o arquivo de regras que você indica — ela não sai coletando
credenciais de páginas nem varrendo o que encontra), e nenhuma operação que altera o alvo é
feita por padrão (sem escrita, sem execução de RPC). Uma allowlist em TOML continua
disponível via `--scope` para quem quiser travar os alvos.

## Relatar uma vulnerabilidade no PermiScan

Não abra issue pública. Use o relato privado de vulnerabilidades do GitHub no repositório
(**Security → Report a vulnerability**), com passos de reprodução e impacto esperado.

## Postura de segurança da ferramenta

### Implementado

| Controle | Como |
|---|---|
| Alvo explícito | Cada comando recebe o alvo diretamente (DSN, URL, página ou arquivo). O `detect` extrai credenciais de uma página/arquivo que você indica; não há varredura automática da web. |
| Somente leitura por padrão | A análise do banco é sempre somente leitura. A Data API, por padrão, só faz `GET`. Os testes que alteram o alvo (`--probe-writes`, `--probe-rpc`) são opt-in e avisam na saída de erro. |
| RPCs destrutivas protegidas | Em `--probe-rpc`, funções de nome destrutivo (delete/drop/admin/…) não são chamadas sem `--include-destructive`; aparecem no relatório como "não chamada". |
| Alvo fixado (banco) | `host`/`port`/`dbname` explícitos sobrepõem variáveis `PG*`; `hostaddr`, `service` e múltiplos hosts são recusados. |
| Somente leitura (banco) | Toda a sessão roda em uma transação `READ ONLY` encerrada com `ROLLBACK`; apenas o catálogo do sistema é consultado. |
| Timeouts | `connect_timeout`/`statement_timeout` de 10 s/30 s no banco; 15 s por requisição na Data API. |
| Credenciais | DSN e chave anon apenas por variável de ambiente, nunca por argumento (evita histórico do shell e listagem de processos). |
| Mascaramento | A senha é removida de mensagens de erro; o `repr` do alvo não inclui credenciais; exceções do driver não são encadeadas. |
| Allowlist opcional | `--scope arquivo.toml` restringe os alvos de banco a uma lista; alvo fora dela é recusado (código de saída 2). |
| Identificação no alvo | Conexões ao banco usam `application_name=permiscan`, visível em `pg_stat_activity` e nos logs do servidor. |

### Planejado

- Testes dinâmicos do banco com identidades e registros sintéticos, sempre em transação
  revertida (M5); prova mínima (contagem em vez de linhas) por padrão.
- Validação de regras do Firebase pelo Emulator Suite (M6).

Criptografia de credenciais em repouso, audit log, workers isolados e rate limiting são
controles de uma implantação multiusuário; como o PermiScan hoje é um CLI local que recebe o
alvo a cada execução, não são implementados. Entram quando (e se) existir a API multiusuário.

## Papel de auditoria recomendado

O PermiScan não precisa de superusuário. Um papel com login e nenhum privilégio extra lê o
catálogo e calcula privilégios efetivos de outros papéis. O laboratório e os testes de
integração rodam exatamente assim.

```sql
CREATE ROLE permiscan_auditor LOGIN PASSWORD '<senha forte>';
-- nenhum GRANT adicional é necessário
```

O `permiscan check` avisa quando a conexão usa um superusuário ou não está em modo
somente leitura.

## Modelo de ameaças (resumo)

| Ativo | Ameaça | Mitigação |
|---|---|---|
| Credenciais do alvo | Vazamento em logs, histórico, saída | DSN por ambiente, redação, sem encadeamento de exceções |
| Alvos de terceiros | Uso contra sistema não autorizado | Allowlist obrigatória; DSN fixado ao alvo validado |
| Integridade do alvo | Escrita ou carga acidental | Banco: transação `READ ONLY`. Data API: escrita e RPC só sob flag explícita, com aviso; RPCs destrutivas exigem `--include-destructive` |
| Exposição de dados na evidência | Amostra de linhas em `--rows`/`scan-api` vaza dados do alvo | Padrão lê 1 linha; valores são truncados na evidência; relatórios ficam locais e no `.gitignore` |
| Relatórios de findings | Exposição do mapa de falhas | Saída local; não versione relatórios (`*.findings.json` no `.gitignore`) |
| Ferramenta | Falso positivo levando a mudança errada | Privilégios efetivos, nível de confiança explícito, remediação revisável |
