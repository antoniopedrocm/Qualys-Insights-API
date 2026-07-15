# IIS Deployment

Guia para Windows Server 2025 Standard com IIS e ASP.NET Core Module.

## 1. Instalar Role Web Server

Execute como Administrador:

```powershell
.\scripts\Install-IISPrerequisites.ps1
```

## 2. Recursos Necessarios Do IIS

- Web Server
- Static Content
- Default Document
- HTTP Errors
- HTTP Logging
- Request Filtering
- Windows Authentication
- IIS Management Console

## 3. Hosting Bundle

Instale o ASP.NET Core Hosting Bundle correspondente ao .NET 10 LTS. O script baixa pelo link `https://aka.ms/dotnet/10.0/dotnet-hosting-win.exe`.

## 4. Diretorio Da Aplicacao

Exemplo:

```powershell
New-Item -ItemType Directory -Force C:\inetpub\QualysInsights
```

## 5. Application Pool

Crie um pool dedicado, por exemplo `QualysInsights`.

## 6. No Managed Code

Configure `.NET CLR version` como `No Managed Code`.

## 7. Pipeline Integrado

Use pipeline `Integrated`.

## 8. Identidade Do App Pool

Use `ApplicationPoolIdentity` ou conta de servico gerenciada. Conceda permissoes minimas.

## 9. Permissoes NTFS

- Pasta da aplicacao: leitura/execucao para `IIS AppPool\QualysInsights`.
- Pasta de dados (`C:\ProgramData\QualysInsights`): leitura/escrita para `IIS AppPool\QualysInsights`.
- Pasta de logs: escrita se logging em arquivo for habilitado externamente.

## 10. Site Ou Aplicacao

Pode ser site raiz:

```text
https://qualys.exemplo.local/
```

ou aplicacao virtual:

```text
https://servidor/qualys/
```

Para aplicacao virtual, configure `Hosting:PathBase=/qualys` se o proxy/IIS nao propagar corretamente.

## 11. Binding HTTPS

Configure binding HTTPS no IIS Manager ou PowerShell.

## 12. Certificado

Use certificado emitido por CA confiavel. Para Qualys com CA corporativa, instale a cadeia no Windows Certificate Store; nao ha bypass TLS na aplicacao.

## 13. Windows Authentication

Habilite Windows Authentication no IIS.

## 14. Anonymous Authentication

Desabilite Anonymous Authentication quando `Authentication:Mode=Windows`.

## 15. Variaveis De Ambiente

Configure no escopo do site, app pool ou sistema:

```text
Qualys__Username
Qualys__Password
Qualys__BaseUrl
Storage__DataDirectory
Authentication__Mode
Authentication__AllowedActiveDirectoryGroups__0
```

## 16. Diretorio De Logs

Use logs do IIS por padrao. Se adicionar provider de arquivo corporativo, garanta permissao de escrita apenas para o App Pool.

## 17. Diretorio De Dados

Default:

```text
C:\ProgramData\QualysInsights
```

Contem `qualys-insights.db` e arquivos auxiliares SQLite.

## 18. Proxy Corporativo

Configure proxy no Windows/ambiente do processo quando necessario. O cliente usa `HttpClientFactory` e a pilha HTTP padrao do .NET.

## 19. Reinicializacao Controlada

Recicle o App Pool em janela de manutencao. O cache SQLite sobrevive ao recycle.

## 20. Validacao

```powershell
.\scripts\Test-Deployment.ps1 -BaseUrl https://qualys.exemplo.local
```

Valide tambem:

- Interface web.
- `/api/hosts`
- `/api/vulnerabilities`
- Download Excel.
- `/health`
- `/health/ready`

## 21. Rollback

O script `Publish-IIS.ps1` cria backup antes de copiar novos arquivos e restaura automaticamente se `/health` falhar.

Exemplo:

```powershell
.\scripts\Publish-IIS.ps1 `
  -SitePath C:\inetpub\QualysInsights `
  -AppPoolName QualysInsights `
  -HealthUrl https://qualys.exemplo.local/health
```

Arquivos de configuracao e banco de dados sao preservados durante a publicacao.

