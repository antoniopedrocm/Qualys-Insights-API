param(
    [string]$HostingBundleUrl = "https://aka.ms/dotnet/10.0/dotnet-hosting-win.exe"
)

$ErrorActionPreference = "Stop"

function Assert-Administrator {
    $principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Execute este script em um PowerShell elevado como Administrador."
    }
}

Assert-Administrator

Write-Host "Instalando recursos do IIS..."
Install-WindowsFeature Web-Server, Web-WebServer, Web-Common-Http, Web-Default-Doc, Web-Static-Content, Web-Http-Errors, Web-Http-Logging, Web-Filtering, Web-Windows-Auth, Web-Mgmt-Console -IncludeManagementTools

$tempInstaller = Join-Path $env:TEMP "dotnet-hosting-win.exe"
Write-Host "Baixando ASP.NET Core Hosting Bundle: $HostingBundleUrl"
Invoke-WebRequest -Uri $HostingBundleUrl -OutFile $tempInstaller

Write-Host "Instalando Hosting Bundle..."
Start-Process -FilePath $tempInstaller -ArgumentList "/quiet", "/norestart" -Wait -WindowStyle Hidden

Write-Host "Reiniciando IIS..."
iisreset

Write-Host "Pre-requisitos instalados."

