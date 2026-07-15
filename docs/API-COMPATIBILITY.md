# API Compatibility

## Mantidos

- `GET /api/health`
- `GET /api/hosts`
- `GET /api/vulnerabilities`
- `POST /api/effectiveness`
- `GET /api/effectiveness/cache`
- `GET /api/scans`
- `GET /api/dashboard/summary`
- `GET /api/dashboard/trends`
- `GET /api/export/vulnerabilities/excel`
- `GET /api/export/vulnerabilities/csv`
- `GET /api/detections/enriched?format=csv|xlsx`
- `POST /efetividade/calcular`

Os nomes de propriedades JSON consumidos pelo frontend foram mantidos em camelCase/lowercase.

## Adicionados

- `GET /health`
- `GET /health/ready`

## Mudancas Intencionais

- A autenticacao Basic fixa `admin/LEGACY_PASSWORD_REMOVED` foi removida.
- O frontend nao envia mais `Authorization: Basic ...`; usa credenciais same-origin para Windows Authentication.
- Requisicoes unsafe (`POST`, `PUT`, `PATCH`, `DELETE`) precisam do header `X-Requested-With: QualysInsights`.
- URLs do frontend agora sao resolvidas de forma relativa para funcionar em `/` e em aplicacoes virtuais como `/qualys/`.

## Fila Qualys

O codigo Qualys `1960` continua retornando HTTP 503 com header `Retry-After` e corpo:

```json
{
  "success": false,
  "error": "Qualys job ainda em execução",
  "message": "...",
  "callsToFinish": 2,
  "retryAfterSeconds": 60
}
```

