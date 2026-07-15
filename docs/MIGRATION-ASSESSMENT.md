# Migration Assessment

Inventario realizado antes da implementacao da migracao Node.js/Express para ASP.NET Core.

## Estado Do Repositorio

- Branch de trabalho: `codex/migrate-to-aspnetcore-iis`.
- Aplicacao atual: Node.js/Express em `server.js`, frontend estatico em `public/`.
- Alteracoes locais preexistentes antes da migracao: `server.js`, `public/index.html`, `public/style.css` e `data/`.
- Cache persistente existente: `data/effectiveness-cache.json`. Deve ser preservado e migrado sem exclusao automatica.
- SDK .NET nao estava instalado no PATH no inicio da avaliacao; a validacao sera feita com SDK local quando necessario.
- Versao alvo escolhida: .NET 10 LTS, ativo ate 2028-11-14 conforme politica oficial Microsoft consultada em 2026-07-15.

## Dependencias Node.js Atuais

- `express`: servidor HTTP e rotas.
- `axios`: cliente HTTP para Qualys.
- `https`: usado para agente TLS customizado.
- `xml2js`: parsing XML.
- `exceljs`: geracao de XLSX.
- `cors`: CORS aberto.
- `dotenv`: leitura de `.env`.
- `express-basic-auth`: autenticacao Basic com fallback inseguro.
- `path` e `fs`: arquivos estaticos, CSV e cache JSON.
- `nodemon`: desenvolvimento.

## Endpoints Existentes

| Metodo | URL | Autenticacao | Comportamento |
| --- | --- | --- | --- |
| GET | `/api/health` | Nao | Retorna status, timestamp, URL Qualys, versao e indicador de credenciais. |
| GET | `/api/hosts` | Basic Auth | Lista hosts Qualys com cache em memoria e retorno stale em falha. |
| GET | `/api/vulnerabilities` | Basic Auth | Lista vulnerabilidades, enriquece com Knowledge Base, trata fila Qualys 1960 e `Retry-After`. |
| POST | `/api/effectiveness` | Basic Auth | Analisa Detection IDs enviados no corpo, classifica open/fixed/invalid e persiste cache de efetividade. |
| GET | `/api/effectiveness/cache` | Basic Auth | Retorna cache persistente de efetividade. |
| GET | `/api/scans` | Basic Auth | Lista scans Qualys. |
| GET | `/api/dashboard/summary` | Basic Auth | Consolida KPIs, severidades, status, top QIDs e distribuicao por tags/janelas. |
| GET | `/api/dashboard/trends` | Basic Auth | Consolida tendencia por `firstFound`. |
| GET | `/api/export/vulnerabilities/excel` | Basic Auth | Exporta XLSX com planilha `Vulnerabilidades`. |
| GET | `/api/export/vulnerabilities/csv` | Basic Auth | Exporta CSV com vulnerabilidades. |
| GET | `/api/detections/enriched` | Basic Auth | Retorna detections enriquecidas; suporta `format=csv` e `format=xlsx`. |
| POST | `/efetividade/calcular` | Basic Auth | Le `detection_ids.csv`, consulta cada Detection ID e retorna resumo por janelas. |
| GET | `*` | Nao | Serve `public/index.html` como fallback SPA. |

## Chamadas Para API Qualys

- `GET /api/2.0/fo/asset/host/`
  - Parametros: `action=list`, `truncation_limit=0`, `show_tags=1`.
  - Origem: listagem de hosts.
- `GET /api/2.0/fo/asset/host/vm/detection/`
  - Parametros principais: `action=list`, `truncation_limit=1000`, `status=New,Active,Re-Opened,Fixed`, `output_format=XML`, `show_tags=1`.
  - Retry legado em HTTP 409 usa `truncation_limit=500`, exceto quando o XML contem codigo Qualys `1960`.
  - Parametro alternativo: `detection_ids=<id>` para consulta individual.
  - Parametro alternativo: `truncation_limit=0` para detections enriquecidas.
- `GET /api/2.0/fo/knowledge_base/vuln/`
  - Parametros: `action=list`, `ids=<qids separados por virgula>`.
  - Usa lotes de 30 QIDs e concorrencia maxima 3.
- `GET /api/2.0/fo/scan/`
  - Parametros: `action=list`.

## Parsers XML

- `parseQueueError`: interpreta `SIMPLE_RETURN/RESPONSE`, campos `CODE`, `CALLS_TO_FINISH`, `TEXT`; codigo `1960` vira erro de fila com `Retry-After`.
- `parseHostXML`: extrai `HOST_LIST_OUTPUT/RESPONSE/HOST_LIST/HOST`; normaliza tags trocando espacos e `/` por `_`.
- `parseHostDetectionXML`: extrai hosts e detections basicas para enriquecimento.
- `parseVulnerabilityXML`: extrai host, tags, QID, severidade, status, `UNIQUE_VULN_ID`, `TYPE`, porta, protocolo, SSL, titulo, solucao e resultados.
- `parseKnowledgeBaseXML`: extrai QID, `UNIQUE_VULN_ID`, titulo e solucao.
- `parseScanXML`: extrai referencia, titulo, tipo, data, estado e alvo.
- `parseDetectionXML`: extrai consulta individual por Detection ID para a rota legada `/efetividade/calcular`.

## Regras De Negocio A Preservar

- Normalizacao de severidade para pt-BR: `Crítica`, `Alta`, `Média`, `Baixa`, `Info`.
- Detection IDs aceitam quebras de linha, virgulas, ponto e virgula, espacos e tabs; duplicados sao removidos.
- Classificacao de efetividade:
  - `invalid`: Detection ID nao numerico.
  - `open`: ID presente no conjunto de detections ativas.
  - `fixed`: ID numerico ausente do conjunto ativo.
- `lastSeen`:
  - usa campos explicitos (`lastSeen`, `lastFound`, `lastDetected`, `lastTest`) quando existem;
  - para open usa timestamp da geracao;
  - para fixed preserva valor previamente persistido quando disponivel.
- Janelas por tags:
  - `DEV_QA`: `DEV_QA`, desenvolvimento, qualidade.
  - `PRD_Baixa`: `PRD_BAIXA`, producao baixa com/sem acento.
  - `PRD_Alta`: `PRD_ALTA`, producao alta com/sem acento.
- Classificacao operacional em exports enriquecidos:
  - `ownerArea`: Legados, Banco de Dados, Aplicacoes_AMS, Windows, Linux, Infraestrutura.
  - `environment`: PRD_Alta, PRD_Baixa, DEV_QAs, Nao classificado.
  - `priority`: P0, P1, P2, P3, P4 ou Nao classificado.
- Dashboard:
  - considera severidades 3, 4 e 5 como relevantes.
  - distribui abertas/corrigidas por tags `DEV_QA`, `PRD_BAIXA`, `PRD_ALTA`.
  - top vulnerabilidades por QID.
  - tendencias por data de primeira deteccao.
- Frontend possui filtros client-side por severidade, busca textual, QID, tags, status, tipo Confirmed/Potential e datas.

## Cache E Persistencia

- Cache em memoria para hosts, vulnerabilidades e Knowledge Base com TTL fixo legado de 300000 ms.
- Retorno stale: se refresh falhar e houver dado anterior, retorna cache antigo com `cached=true` e `stale=true`.
- Cache persistente de efetividade em JSON:
  - caminho legado: `data/effectiveness-cache.json`.
  - objeto `meta` com `generatedAt`, `source`, `version`.
  - objeto `itemsByDetectionId` indexado por Detection ID.
  - gravacao atomica legada por arquivo `.tmp` + rename.
- Migracao recomendada: SQLite/EF Core com migracao opcional do JSON legado, sem apagar o arquivo original.

## Arquivos E Recursos Estaticos

- `public/index.html`: shell da interface, abas Dashboard, Vulnerabilidades, Efetividade, Hosts, Scans e API Explorer.
- `public/app.js`: logica do frontend, chamadas API, filtros, graficos Chart.js, exportacoes CSV client-side.
- `public/style.css`: tema visual escuro responsivo.
- `public/index_.html`: copia/variante legada.
- Dependencias externas no frontend: Google Fonts, Chart.js via CDN e Lucide via CDN.

## Arquivos JavaScript

- `server.js`: servidor, Qualys API, parsers, regras, rotas e exports.
- `src/effectiveness.js`: parsing e classificacao de Detection IDs.
- `src/severity.js`: normalizacao de severidade.
- `src/cache/effectivenessCache.js`: cache JSON persistente da efetividade.
- `src/ExecutiveDashboard.jsx`: componente React isolado/mockado, nao integrado ao servidor Express atual.
- `test-credentials.js` e `test-qualys.js`: scripts manuais de validacao Qualys.
- Testes Node em `test/*.test.js`.

## JSON, CSV E Dados

- `.env.example`: placeholders, mas ainda contem defaults inseguros para API web (`admin`/`LEGACY_PASSWORD_REMOVED`).
- `.env`: presente localmente e ignorado pelo Git; nao deve ser versionado.
- `detection_ids.csv`: entrada da rota legada `/efetividade/calcular`.
- `data/effectiveness-cache.json`: cache persistente real/local; nao deve ser apagado nem sobrescrito sem backup.
- `package.json` e `package-lock.json`: devem ser preservados em `legacy-node/`.
- `patch.diff` e `server - Copia.js.bkp`: artefatos legados a preservar em `legacy-node/`.

## Seguranca Encontrada

- TLS desabilitado no cliente Qualys por `rejectUnauthorized: true`; deve ser removido na migracao.
- Basic Auth atual possui fallback `admin/LEGACY_PASSWORD_REMOVED`; deve ser removido.
- Frontend injeta `Authorization: Basic admin:LEGACY_PASSWORD_REMOVED`; deve ser removido.
- CORS atual e aberto por `app.use(cors())`; deve virar politica restritiva configuravel.
- Logs atuais podem expor usuario/senha da API web e informacoes sensiveis; devem ser mascarados.
- CSV/XLSX nao protegem contra Formula Injection; exportacoes devem prefixar valores perigosos.
- Tratamento de erro atual expõe mensagens brutas; migracao deve usar `ProblemDetails` sem stack trace em producao.

## Testes Existentes

- `test/severity.test.js`: normalizacao de severidade.
- `test/effectiveness.test.js`: parsing e classificacao de Detection IDs.
- `test/effectivenessCache.test.js`: merge de cache persistente.
- Nao existem testes automatizados para XML, endpoints, exportacao, seguranca, autenticacao ou Qualys queue.

## Contratos A Preservar

- Propriedades JSON em camelCase/lowercase ja consumidas pelo frontend.
- Estrutura de resposta padrao:
  - `success`
  - `total`
  - `cached`
  - `stale`
  - `data`
  - `error`
  - `message`
- Fila Qualys:
  - HTTP 503.
  - Header `Retry-After`.
  - Corpo com `success=false`, `error`, `message`, `callsToFinish`, `retryAfterSeconds` e possivel payload cacheado.
- Downloads:
  - XLSX `qualys_vulnerabilities_<timestamp>.xlsx`.
  - CSV `qualys_vulnerabilities_<timestamp>.csv`.
  - Detections enriquecidas `detections.csv` e `detections.xlsx`.
- SPA fallback deve continuar servindo a interface.

## Mudancas De Contrato Previstas

- Remocao de Basic Auth fixo no frontend. A autenticacao sera Windows Authentication por padrao, com modo customizado apenas se explicitamente configurado.
- URLs do frontend serao baseadas em caminho relativo e `PathBase` para funcionar na raiz e em aplicacao virtual IIS.
- `GET /health` e `GET /health/ready` serao adicionados; `/api/health` sera mantido por compatibilidade.

