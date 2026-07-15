# Migration Report

## Resumo

A aplicacao foi migrada de Node.js/Express para ASP.NET Core `net10.0`, com separacao em Web, Application e Infrastructure, frontend preservado em `wwwroot`, SQLite para efetividade e scripts de IIS.

## Funcionalidades Preservadas

- Hosts, vulnerabilidades, scans e Knowledge Base.
- Enriquecimento por QID.
- Dashboard, tendencias e distribuicao por tags/janelas.
- Efetividade por Detection ID com status open/fixed/invalid.
- Exports CSV/XLSX.
- Tratamento de fila Qualys `1960` e `Retry-After`.
- Cache em memoria com stale.
- Cache persistente de efetividade com migracao do JSON legado.

## Validacao

Executado com sucesso:

```powershell
dotnet build QualysInsights.sln -c Release
dotnet test QualysInsights.sln -c Release
```

Resultado dos testes:

- 17 testes unitarios aprovados.
- 4 testes de integracao aprovados.

## Pendencias Externas

- Configurar credenciais Qualys por variaveis de ambiente, Windows Credential Manager ou secret store corporativo.
- Definir grupos AD em `Authentication:AllowedActiveDirectoryGroups`.
- Instalar Hosting Bundle .NET 10 no servidor IIS.
- Configurar certificado HTTPS e bindings no IIS.

