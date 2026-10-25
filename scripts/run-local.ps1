$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location -LiteralPath $projectRoot
$env:APP_ENV = 'development'
$dataDir = Join-Path $projectRoot 'data'
New-Item -ItemType Directory -Path $dataDir -Force | Out-Null
$secretFile = Join-Path $dataDir 'local-app-secret'
if (Test-Path -LiteralPath $secretFile) {
    $env:APP_SECRET = (Get-Content -LiteralPath $secretFile -Raw).Trim()
} else {
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    $secretBytes = New-Object byte[] 48
    $rng.GetBytes($secretBytes)
    $rng.Dispose()
    $env:APP_SECRET = [Convert]::ToBase64String($secretBytes)
    Set-Content -LiteralPath $secretFile -Value $env:APP_SECRET -NoNewline
}
$dbFile = (Join-Path $projectRoot 'data\local-preview.db').Replace('\', '/')
$env:DATABASE_URL = "sqlite:///$dbFile"
$env:DATA_ENCRYPTION_KEY = ''
$adminInviteFile = Join-Path $dataDir 'local-admin-invite-code'
if (Test-Path -LiteralPath $adminInviteFile) {
    $env:ADMIN_INVITE_CODE = (Get-Content -LiteralPath $adminInviteFile -Raw).Trim()
} else {
    $inviteBytes = New-Object byte[] 48
    $inviteRng = [Security.Cryptography.RandomNumberGenerator]::Create()
    $inviteRng.GetBytes($inviteBytes)
    $inviteRng.Dispose()
    $env:ADMIN_INVITE_CODE = [Convert]::ToBase64String($inviteBytes)
    Set-Content -LiteralPath $adminInviteFile -Value $env:ADMIN_INVITE_CODE -NoNewline
}
$env:TOKEN_ENCRYPTION_KEY = ''
$pythonPath = (Get-Command python).Source
$worker = Start-Process -FilePath $pythonPath -ArgumentList @('-m', 'api.worker') -WorkingDirectory $projectRoot -WindowStyle Hidden -PassThru
Write-Host 'CareCircle preview: http://127.0.0.1:8765'
Write-Host 'Local SQLite database and background worker are active. Windows user encryption protects private fields.'
try {
    python -m uvicorn api.main:app --host 127.0.0.1 --port 8765
}
finally {
    if ($worker -and -not $worker.HasExited) { Stop-Process -Id $worker.Id -Force -ErrorAction SilentlyContinue }
}
