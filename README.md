# Qualys Insights API

Aplicacao corporativa ASP.NET Core para dashboard, relatorios e analise de efetividade com dados da API Qualys.

## Estrutura

- `src/QualysInsights.Web`: API, controllers, middlewares, autenticacao e frontend estatico em `wwwroot`.
- `src/QualysInsights.Application`: DTOs, contratos e regras de negocio.
- `src/QualysInsights.Infrastructure`: cliente Qualys, XML, cache, SQLite e exportacao XLSX/CSV.
- `tests/`: testes unitarios e de integracao com Qualys mockado.
- `legacy-node/`: aplicacao Node.js/Express original preservada para consulta e rollback.
- `docs/`: avaliacao, arquitetura, seguranca, compatibilidade e implantacao IIS.
- `scripts/`: automacao de pre-requisitos, publicacao e validacao no IIS.

## Configuracao

Use variaveis de ambiente ou um arquivo de configuracao externo ao repositorio:

```powershell
$env:Qualys__Username = "usuario"
$env:Qualys__Password = "senha"
$env:Qualys__BaseUrl = "https://qualysguard.qg3.apps.qualys.com"
$env:Storage__DataDirectory = "C:\ProgramData\QualysInsights"
$env:Authentication__Mode = "Windows"
```

O arquivo `src/QualysInsights.Web/appsettings.Example.json` contem placeholders sem segredos.

## Comandos

```powershell
dotnet restore
dotnet build -c Release
dotnet test -c Release
dotnet publish .\src\QualysInsights.Web\QualysInsights.Web.csproj -c Release -o .\publish
```

Neste ambiente foi usado SDK local em `.dotnet` porque o `dotnet` nao estava instalado globalmente.

