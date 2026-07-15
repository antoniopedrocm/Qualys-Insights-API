param(
    [Parameter(Mandatory = $true)]
    [string]$BaseUrl,

    [int]$TimeoutSeconds = 30
)

$ErrorActionPreference = "Stop"

function Invoke-Health($path) {
    $uri = ($BaseUrl.TrimEnd("/") + $path)
    Write-Host "Testando $uri"
    Invoke-WebRequest -Uri $uri -UseDefaultCredentials -TimeoutSec $TimeoutSeconds
}

$health = Invoke-Health "/health"
if ($health.StatusCode -ne 200) {
    throw "/health retornou HTTP $($health.StatusCode)"
}

$ready = Invoke-Health "/health/ready"
if ($ready.StatusCode -ne 200) {
    throw "/health/ready retornou HTTP $($ready.StatusCode)"
}

Write-Host "Deploy validado com sucesso."

