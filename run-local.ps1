# Starts the Zero Trust application locally.
# Needs MongoDB running (default mongodb://localhost:27017). Optionally prompts for
# a MongoDB connection string and the initial admin password without echoing the
# latter, and keeps them only in this PowerShell session.

$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

if (-not $env:MONGODB_URI) {
    Write-Host "MongoDB connection string (press Enter for mongodb://localhost:27017/zero_trust_db)."
    $uri = Read-Host "MONGODB_URI"
    if (-not [string]::IsNullOrWhiteSpace($uri)) { $env:MONGODB_URI = $uri }
}

if (-not $env:ZT_ADMIN_PASSWORD) {
    Write-Host "Initial admin password (used only on the very first start; press Enter to generate a random one)."
    $secureAdmin = Read-Host "Admin password" -AsSecureString
    $plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureAdmin))
    if (-not [string]::IsNullOrWhiteSpace($plain)) { $env:ZT_ADMIN_PASSWORD = $plain }
}

Write-Host "Starting Zero Trust on http://localhost:8080 ..." -ForegroundColor Cyan
mvn spring-boot:run
