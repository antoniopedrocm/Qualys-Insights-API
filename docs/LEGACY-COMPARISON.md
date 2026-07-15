# Legacy Comparison

## Legado Node.js

Preservado em `legacy-node/`:

- `server.js`
- `public/`
- `src/`
- `test/`
- `package.json`
- `package-lock.json`
- `detection_ids.csv`
- scripts manuais e backup existentes

## Equivalencias

- Express routes viraram controllers ASP.NET Core.
- `axios` virou `HttpClientFactory`.
- `xml2js` virou parser com `System.Xml.Linq`.
- `ExcelJS` virou ClosedXML.
- Cache em memoria manual virou `MemoryCachedDataProvider`.
- Cache JSON de efetividade virou SQLite, com migracao opcional do JSON legado.
- Static files de `public/` foram migrados para `wwwroot/`.

## Rollback

O rollback funcional esta documentado em `docs/IIS-DEPLOYMENT.md`. O legado nao foi removido e o cache JSON antigo nao e apagado pela migracao.

