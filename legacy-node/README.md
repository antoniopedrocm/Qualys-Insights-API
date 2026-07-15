# Qualys Security Dashboard

Dashboard web para visualização de vulnerabilidades e análise de efetividade de correções com dados do Qualys.

## 🚀 Instalação

```bash
npm install
npm start
```

A aplicação sobe em `http://localhost:3000`.

## 📈 Efetividade

Na aba **Efetividade** você pode:

- Colar Detection IDs (separados por quebra de linha, vírgula, ponto e vírgula, espaço ou tabulação).
- Clicar em **Analisar** para classificar os IDs em:
  - **Pendentes**: ainda ativos no Qualys.
  - **Corrigidas**: não encontrados entre as detecções ativas.
  - **Inválidas**: IDs não numéricos.
- Visualizar resumo, gráficos (incluindo severidade x status e distribuição por severidade), filtros e tabela detalhada.

### Cache local em arquivo único

O backend persiste os dados enriquecidos da efetividade em:

- `data/effectiveness-cache.json`

Esse arquivo inclui `meta` e `itemsByDetectionId`, com os campos:

- `detectionId`
- `status` (`open`, `fixed`, `invalid`)
- `dns`
- `ip`
- `title`
- `severity` (normalizada em pt-BR)
- `solution`
- `hostTags` (array)
- `lastSeen` (Última Visualização)

Para limpar o cache, basta remover o arquivo:

```bash
rm -f data/effectiveness-cache.json
```

> Se o arquivo não existir, ele é criado automaticamente na próxima chamada do endpoint.

### Endpoints da Efetividade

#### `POST /api/effectiveness`

Payload:

```json
{ "detectionIds": ["6385789118", "6385789120"] }
```

Resposta (resumo):

```json
{
  "success": true,
  "total": 2,
  "fixed": 1,
  "open": 1,
  "invalid": 0,
  "filters": {
    "severities": ["Crítica", "Alta", "Média"],
    "hostTags": ["SAP", "PRD"]
  },
  "items": [
    {
      "detectionId": "6385789118",
      "status": "open",
      "dns": "gowsap36.pratika.br",
      "ip": "10.62.3.36",
      "severity": "Crítica",
      "hostTags": ["SAP", "PRD", "Windows"],
      "lastSeen": "2026-02-18T03:12:00.000Z"
    }
  ]
}
```

#### `GET /api/effectiveness/cache`

Retorna o conteúdo do cache persistido (`meta` + `items`).
