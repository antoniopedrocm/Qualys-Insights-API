# Qualys Security Dashboard

Dashboard para visualização e análise de vulnerabilidades do Qualys.

## 🚀 Instalação

1. Clone o repositório
2. Instale as dependências:
   ```bash
   npm install
   ```
3. Configure as credenciais:
   ```bash
   cp .env.example .env
   ```
4. Edite o arquivo `.env` e adicione suas credenciais do Qualys.

## ⚙️ Configuração

Edite o arquivo `.env` com suas credenciais:
```env
QUALYS_USERNAME=seu_usuario_qualys
QUALYS_PASSWORD=sua_senha_qualys
QUALYS_BASE_URL=https://qualysguard.qg3.apps.qualys.com

API_USERNAME=admin
API_PASSWORD=admin123

PORT=3000
```

## 🏃 Executar
```bash
npm start
```

Acesse: `http://localhost:3000`

## 📚 Documentação

- Credenciais da API Web: `admin` / `admin123` (configurável no `.env`)
- Endpoints disponíveis em `/api/*`
