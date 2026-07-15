param(
    [string]$ProjectPath = ".\src\QualysInsights.Web\QualysInsights.Web.csproj",
    [string]$PublishOutput = ".\publish",
    [Parameter(Mandatory = $true)]
    [string]$SitePath,
    [Parameter(Mandatory = $true)]
    [string]$AppPoolName,
    [Parameter(Mandatory = $true)]
    [string]$HealthUrl,
    [string]$BackupRoot = ".\deploy-backups",
    [string[]]$PreserveFiles = @("appsettings.Production.json", "appsettings.json", "qualys-insights.db", "qualys-insights.db-shm", "qualys-insights.db-wal")
)

$ErrorActionPreference = "Stop"

function Assert-Administrator {
    $principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Execute este script em um PowerShell elevado como Administrador."
    }
}

function Assert-IIS {
    if (-not (Get-Command Get-WebAppPoolState -ErrorAction SilentlyContinue)) {
        Import-Module WebAdministration -ErrorAction Stop
    }
}

function Test-HostingBundle {
    $aspNetCoreModule = Join-Path $env:ProgramFiles "IIS\Asp.Net Core Module\V2\aspnetcorev2.dll"
    if (-not (Test-Path $aspNetCoreModule)) {
        throw "ASP.NET Core Hosting Bundle nao encontrado. Instale o Hosting Bundle .NET 10."
    }
}

function Copy-PreserveFiles($source, $destination) {
    foreach ($file in $PreserveFiles) {
        $sourcePath = Join-Path $source $file
        if (Test-Path -LiteralPath $sourcePath) {
            New-Item -ItemType Directory -Force -Path $destination | Out-Null
            Copy-Item -LiteralPath $sourcePath -Destination (Join-Path $destination $file) -Force
        }
    }
}

Assert-Administrator
Assert-IIS
Test-HostingBundle

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$resolvedSitePath = [IO.Path]::GetFullPath($SitePath)
$resolvedPublish = [IO.Path]::GetFullPath($PublishOutput)
$backupPath = [IO.Path]::GetFullPath((Join-Path $BackupRoot "backup-$timestamp"))
$preservePath = Join-Path $env:TEMP "qualys-insights-preserve-$timestamp"
$deployLog = Join-Path $BackupRoot "deploy-$timestamp.log"

New-Item -ItemType Directory -Force -Path $BackupRoot | Out-Null

try {
    "Deploy iniciado em $(Get-Date -Format o)" | Tee-Object -FilePath $deployLog

    dotnet publish $ProjectPath -c Release -o $resolvedPublish | Tee-Object -FilePath $deployLog -Append

    if (Test-Path -LiteralPath $resolvedSitePath) {
        New-Item -ItemType Directory -Force -Path $backupPath | Out-Null
        Copy-Item -Path "$resolvedSitePath\*" -Destination $backupPath -Recurse -Force -ErrorAction SilentlyContinue
        Copy-PreserveFiles -source $resolvedSitePath -destination $preservePath
    }

    if ((Get-WebAppPoolState -Name $AppPoolName).Value -ne "Stopped") {
        Stop-WebAppPool -Name $AppPoolName
    }

    New-Item -ItemType Directory -Force -Path $resolvedSitePath | Out-Null
    Get-ChildItem -LiteralPath $resolvedSitePath -Force | Remove-Item -Recurse -Force
    Copy-Item -Path "$resolvedPublish\*" -Destination $resolvedSitePath -Recurse -Force
    Copy-PreserveFiles -source $preservePath -destination $resolvedSitePath

    $acl = Get-Acl $resolvedSitePath
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule("IIS AppPool\$AppPoolName", "ReadAndExecute, Synchronize", "ContainerInherit,ObjectInherit", "None", "Allow")
    $acl.SetAccessRule($rule)
    Set-Acl -LiteralPath $resolvedSitePath -AclObject $acl

    Start-WebAppPool -Name $AppPoolName
    Start-Sleep -Seconds 5

    $health = Invoke-WebRequest -Uri $HealthUrl -UseDefaultCredentials -TimeoutSec 30
    if ($health.StatusCode -ne 200) {
        throw "Health check retornou HTTP $($health.StatusCode)"
    }

    "Deploy concluido em $(Get-Date -Format o)" | Tee-Object -FilePath $deployLog -Append
}
catch {
    "Falha no deploy: $($_.Exception.Message)" | Tee-Object -FilePath $deployLog -Append

    if (Test-Path -LiteralPath $backupPath) {
        Write-Warning "Executando rollback a partir de $backupPath"
        Stop-WebAppPool -Name $AppPoolName -ErrorAction SilentlyContinue
        Get-ChildItem -LiteralPath $resolvedSitePath -Force | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        Copy-Item -Path "$backupPath\*" -Destination $resolvedSitePath -Recurse -Force
        Start-WebAppPool -Name $AppPoolName
    }

    throw
}
finally {
    if (Test-Path -LiteralPath $preservePath) {
        Remove-Item -LiteralPath $preservePath -Recurse -Force
    }
}
