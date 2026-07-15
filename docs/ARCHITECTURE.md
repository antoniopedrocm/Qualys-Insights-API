# Architecture

## Visao Geral

A migracao usa ASP.NET Core Web API com controllers, injeção de dependencia nativa, `IHttpClientFactory`, XML via `System.Xml.Linq`, cache em memoria e SQLite para persistencia da efetividade.

```text
QualysInsights.Web
  Controllers, Middleware, Security, wwwroot
QualysInsights.Application
  DTOs, Interfaces, Services, Options
QualysInsights.Infrastructure
  Qualys client/parser, caching, SQLite, export, files
```

## Fluxo Principal

1. Controller recebe requisicao.
2. `QualysDataService` aplica cache e regras de negocio.
3. `IQualysClient` consulta a API Qualys com Basic Auth tipado e retry controlado.
4. `QualysXmlParser` converte XML para DTOs.
5. Dados de efetividade sao persistidos em SQLite.
6. Frontend estatico em `wwwroot` consome os mesmos endpoints.

## Cache

- Hosts e vulnerabilidades usam cache em memoria com TTL configuravel.
- Se o refresh falha e ha dado anterior, o servico retorna stale quando `Cache:AllowStaleOnFailure=true`.
- Knowledge Base possui cache em memoria interno, com concorrencia e lote configuraveis.
- Efetividade usa SQLite com indice por Detection ID.

## Background Refresh

`BackgroundRefresh:Enabled=false` por padrao. Quando habilitado, um `BackgroundService` atualiza hosts e vulnerabilidades periodicamente sem bloquear a inicializacao do site.

