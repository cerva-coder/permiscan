# Contribuindo

## Ambiente

```sh
uv sync
docker compose up -d --wait lab-db
export PERMISCAN_LAB_DSN=postgresql://permiscan_auditor:auditor-lab-only@127.0.0.1:55432/permiscan_lab
uv run pytest
```

Sem `PERMISCAN_LAB_DSN` os testes de integração são pulados; o CI sempre os executa.
Use `127.0.0.1` e não `localhost`: o laboratório escuta só em IPv4, e `localhost` pode
resolver primeiro para `::1`, o que custa um timeout por conexão.

Para recriar o laboratório depois de alterar os SQL: `docker compose down -v && docker compose up -d --wait lab-db`.

## Adicionando uma regra PostgreSQL

1. Escreva uma função `(snapshot, provider) -> Iterator[Finding]` em
   `permiscan/adapters/postgres/rules.py` e inclua-a em `RULES`.
2. Cruze sempre a configuração com os privilégios efetivos (`Relation.privileges`,
   `Function.executable_by`): sem papel capaz de exercer a operação, não há finding.
3. Se precisar de dados novos do catálogo, estenda o `Snapshot` em `catalog.py`.
4. Testes unitários em `tests/unit/test_rules.py` com um caso vulnerável **e** um seguro.
5. Adicione um objeto vulnerável em `tests/fixtures/lab/10_vulnerable.sql`, um seguro em
   `20_safe.sql`, e atualize o conjunto esperado em `tests/integration/test_lab.py`.
6. Documente a regra na tabela do README.

Confiança: `likely` quando o catálogo prova a condição; `possible` quando depende de
heurística ou intenção; `confirmed` só a partir de teste dinâmico.

## Adicionando um provedor

Implemente `permiscan.adapters.base.Adapter`, declare em `capabilities` apenas o que está
implementado e registre em `permiscan/adapters/__init__.py`. Atualize a tabela de status do
README. Não declare suporte sem validar a integração; se faltar credencial para validar,
documente o que foi testado e como.

## Convenções

- Textos para o usuário e comentários em português; identificadores em inglês.
- Commits no formato Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`, `chore:`).
- Fixtures apenas com dados sintéticos. Nunca versione credenciais, DSNs reais ou relatórios
  de alvos reais.
