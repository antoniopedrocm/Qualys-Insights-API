# Security

## Corrigido

- Removido bypass TLS equivalente a `rejectUnauthorized: true`.
- Removidas credenciais fixas `admin/LEGACY_PASSWORD_REMOVED`.
- Segredos Qualys nao ficam no codigo nem em `appsettings.json`.
- `.gitignore` protege `.env`, bancos locais, certificados, chaves e dados.
- CORS e configuravel e fechado por padrao.
- Headers de seguranca aplicados:
  - `Content-Security-Policy`
  - `X-Frame-Options: DENY`
  - `X-Content-Type-Options: nosniff`
  - `Referrer-Policy`
  - `Permissions-Policy`
- Exportacoes CSV/XLSX protegem contra Formula Injection para valores iniciados por `=`, `+`, `-` ou `@`.
- Erros inesperados usam `ProblemDetails` sem stack trace em producao.
- Endpoints pesados usam rate limiting.
- Requisicoes unsafe exigem `X-Requested-With`.

## Autenticacao

Modos configuraveis:

- `Windows`: recomendado para IIS, usando Windows Authentication e grupos AD opcionais.
- `ApiKey`: autenticacao propria por header `X-QualysInsights-ApiKey`, validado contra hash SHA-256 configurado.
- `Disabled`: apenas para desenvolvimento/testes.

## TLS Corporativo

A cadeia TLS do Qualys deve ser confiada pelo Windows Certificate Store. Caso haja CA corporativa privada, instale a cadeia no repositório de Autoridades Raiz/Intermediarias confiaveis do Windows. A aplicacao nao implementa bypass global de certificado.

