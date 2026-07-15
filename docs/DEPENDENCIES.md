# Dependencies

## Runtime

- .NET 10 LTS (`net10.0`), escolhido por ser LTS oficialmente suportado na data da migracao. Referencia: https://dotnet.microsoft.com/en-us/platform/support/policy/dotnet-core
- ASP.NET Core Module via Hosting Bundle .NET 10 para IIS.

## NuGet

- `Microsoft.AspNetCore.Authentication.Negotiate`: Windows Authentication.
- `Microsoft.EntityFrameworkCore.Sqlite`: cache persistente de efetividade em SQLite.
- `SQLitePCLRaw.bundle_e_sqlite3` `2.1.12`: fixado para evitar a versao transitiva vulneravel `2.1.11`.
- `ClosedXML` `0.105.0`: geracao XLSX. Licenca MIT conforme NuGet Gallery: https://www.nuget.org/packages/ClosedXML/0.105.0
- `Microsoft.AspNetCore.Mvc.Testing`: testes de integracao.
- `xunit`: testes unitarios e de integracao.

## Removidos Da Producao

- Node.js
- Express
- axios
- xml2js
- ExcelJS
- express-basic-auth
- dotenv

Esses pacotes permanecem apenas em `legacy-node/` como referencia historica.
