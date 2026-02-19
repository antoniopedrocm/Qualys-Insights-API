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
- Visualizar resumo, gráficos e tabela detalhada.

### Endpoint usado pela tela

`POST /api/effectiveness`

Payload:

```json
{ "detectionIds": ["6385789118", "6385789120"] }
```

Resposta:

```json
{
  "success": true,
  "total": 2,
  "fixed": 1,
  "open": 1,
  "invalid": 0,
  "items": [
    { "detectionId": "6385789118", "status": "open", "dns": "...", "ip": "..." }
  ]
}
```
