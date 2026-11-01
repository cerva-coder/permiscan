# Segurança

## Uso autorizado

O PermiScan é uma ferramenta de segurança defensiva. Use-a somente em sistemas que são
seus ou que você tem autorização expressa e documentada para avaliar: suas aplicações,
avaliações contratadas, ambientes de laboratório e aplicações intencionalmente vulneráveis.

A ferramenta reforça isso tecnicamente: sem um arquivo de escopo que declare o alvo, nenhuma
conexão é aberta.

## Relatar uma vulnerabilidade no PermiScan

Não abra issue pública. Use o relato privado de vulnerabilidades do GitHub no repositório
(**Security → Report a vulnerability**), com passos de reprodução e impacto esperado.

## Postura de segurança da ferramenta

### Implementado

| Controle | Como |
|---|---|
| Escopo explícito | Allowlist em TOML; alvo fora dela é recusado antes de qualquer conexão (código de saída 2). |
| Alvo fixado | `host`/`port`/`dbname` explícitos sobrepõem variáveis `PG*`; `hostaddr`, `service` e múltiplos hosts são recusados. |
| Somente leitura | Toda a sessão roda em uma transação `READ ONLY` encerrada com `ROLLBACK`. |
| Extração mínima | Apenas o catálogo do sistema é consultado; nenhuma linha de tabela de usuário é lida. |
| Timeouts | `connect_timeout` de 10 s e `statement_timeout` de 30 s. |
| Credenciais | DSN apenas por variável de ambiente, nunca por argumento (evita histórico do shell e listagem de processos). |
| Mascaramento | A senha é removida de mensagens de erro; o `repr` do alvo não inclui credenciais; exceções do driver não são encadeadas. |
| Identificação no alvo | Conexões usam `application_name=permiscan`, visível em `pg_stat_activity` e nos logs do servidor. |

### Planejado

- Criptografia de credenciais em repouso e AuditLog (M1).
- Workers isolados, limites de concorrência, rate limiting e cancelamento (M1).
- Testes dinâmicos com identidades e registros sintéticos, sempre em transação revertida,
  exigindo modo `dynamic` autorizado no escopo (M5).
- Sanitização de evidências: provas mínimas em vez de registros completos (M5).

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
| Integridade do alvo | Escrita ou carga acidental | Transação `READ ONLY`, timeouts, apenas consultas ao catálogo |
| Relatórios de findings | Exposição do mapa de falhas | Saída local; não versione relatórios (`*.findings.json` no `.gitignore`) |
| Ferramenta | Falso positivo levando a mudança errada | Privilégios efetivos, nível de confiança explícito, remediação revisável |
