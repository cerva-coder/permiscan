# Melhorias na Detecção de Supabase

## Problemas Identificados

### 1. Detecção de Chaves Muito Restritiva
**Antes**: O regex só aceitava JWTs com `iss=supabase` ou `role=anon/service_role`
**Depois**: Agora aceita também:
- JWTs com `aud` e `ref` (estrutura típica de Supabase)
- Chaves dos formatos `sb_publishable_*` e `sb_secret_*`
- JWTs com `role=authenticated`

### 2. URLs Inválidas no Código
**Problema**: Sites tinham URLs Supabase antigas/inválidas no código (ex: `ptcbzfqtbxtuzpiblwsd.supabase.co`)
**Solução**:
- Filtra URLs óbvias de placeholder: `undefined`, `null`, `your-project`, `example`, `test`
- Detecta URLs que não resolvem no DNS e reporta como finding MEDIUM
- Mensagem clara: "URL Supabase inválida detectada no código"

### 3. Mismatch entre Chave e URL
**Problema**: Chave detectada não correspondia à URL do projeto (erro 401)
**Solução**:
- Detecta erro 401 e reporta como finding LOW
- Mensagem explicativa sobre mismatch
- Sugere uso de `scan-api` com credenciais corretas

### 4. Comando `detect` Não Baixava Scripts
**Antes**: Só baixava o HTML da página
**Depois**: Agora baixa também os scripts JS (igual ao `recon`)
- As chaves Supabase frequentemente estão em bundles JS minificados
- Melhora significativa na detecção

### 5. Tratamento de Erros Mais Robusto
**Antes**: Erros em uma instância Supabase falhavam o scan inteiro
**Depois**:
- Captura erros individualmente por instância
- Reporta como findings informativos
- Continua escaneando outras instâncias

### 6. User-Agent em Requisições
**Antes**: Algumas sites bloqueavam requisições sem User-Agent
**Depois**: Adiciona User-Agent realista nas requisições HTTP

## Testes Realizados

### tudoall.com.br
- **Resultado**: Detectou URL Supabase inválida (`ptcbzfqtbxtuzpiblwsd.supabase.co`)
- **Finding**: URL inválida no código (DNS não resolve)
- **Causa**: URL antiga deixada no código fonte

### raioxcomercial.com.br
- **Resultado**: Detectou Supabase com chave anon
- **Problema**: Chave rejeitada pela URL (HTTP 401)
- **Finding**: Chave não corresponde à URL
- **Causa**: Chave expirada, revogada, ou de projeto diferente

### plany.digital
- **Resultado**: Detectou Firebase, não Supabase
- **Status**: Nenhuma exposição

### belezabrasileira.com.br
- **Resultado**: Nenhuma stack detectada
- **Status**: Apenas Cloudflare, sem banco exposto

## Recomendações para Usuários

1. **Para sites que não detectam Supabase**:
   - Use `permiscan detect --url <url>` para ver o que está sendo detectado
   - Verifique se o site realmente usa Supabase (pode usar Firebase, PostgreSQL direto, etc.)

2. **Para sites com URL inválida**:
   - O site tem código morto/antigo
   - A URL precisa ser removida ou atualizada no código fonte

3. **Para sites com mismatch chave/URL**:
   - Use `permiscan scan-api --url <CORRECT_URL> --key <CORRECT_KEY>`
   - Obtenha a chave correta no Supabase Dashboard

4. **Lista de sites "autorizados"**:
   - A lista pode estar desatualizada
   - Sites podem ter migrado de Supabase para outro banco
   - Verifique manualmente cada site

## Limitações

1. **Sites sem chaves públicas**: Se o site não tem a chave anon no frontend, o `recon` não consegue escanear
2. **Sites com código ofuscado**: Bundles muito ofuscados podem esconder as chaves
3. **Sites com CORS bloqueado**: Mesmo com chave, pode não conseguir conectar via cliente
4. **Projetos Supabase desativados**: URLs podem existir mas o projeto foi desativado

## Próximas Melhorias Sugeridas

1. Adicionar modo de debug detalhado (`--debug`) para mostrar HTML/JS baixado
2. Tentar múltiplas estratégias de detecção (headers, meta tags, etc.)
3. Cache de resultados para evitar downloads repetidos
4. Opção para fornecer chave manualmente quando detectada mas inválida
5. Detectar e reportar quando há múltiplas instâncias Supabase no mesmo site
