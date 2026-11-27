<#
.SYNOPSIS
  Builds C:\PCPorter-dist\PCPorter.zip for another PC: the published EXE and its DLLs, HOW-TO-RUN.txt and baseline.ps1.

.DESCRIPTION
  Publishes to the dist folder (same place regress.ps1 -Level release tests), then zips the published files together
  with packaging\HOW-TO-RUN.txt and scripts\regress\baseline.ps1. -NoPublish zips what is already in the dist folder,
  e.g. right after a passing release run. Prints the zip's and the EXE's SHA-256.
#>
#Requires -Version 7
param(
    [string] $Dist = 'C:\PCPorter-dist\PCPorter',
    [string] $Zip = 'C:\PCPorter-dist\PCPorter.zip',
    [switch] $NoPublish
)
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent

if (-not $NoPublish) {
    dotnet publish (Join-Path $repo 'src\PCPorter.App') -p:PublishProfile=win-x64 -o $Dist -nologo -v q
    if ($LASTEXITCODE -ne 0) { Write-Host 'PUBLISH FAILED' -ForegroundColor Red; exit 2 }
}
$howTo = Join-Path $repo 'packaging\HOW-TO-RUN.txt'
Copy-Item $howTo (Join-Path $Dist 'HOW-TO-RUN.txt') -Force   # keeps the folder copy in step with the repo

# The published files plus the extras. baseline.ps1 is not copied into the dist folder: the smoke run checks that the
# folder holds exactly the published files.
$files = @(Get-ChildItem -LiteralPath $Dist -File) + (Get-Item (Join-Path $repo 'scripts\regress\baseline.ps1'))
if (-not ($files | Where-Object Name -eq 'PCPorter.exe')) { Write-Host "No PCPorter.exe in $Dist" -ForegroundColor Red; exit 2 }
Remove-Item $Zip -ErrorAction SilentlyContinue
Compress-Archive -LiteralPath $files.FullName -DestinationPath $Zip -CompressionLevel Optimal

Get-Item $Zip | ForEach-Object { '{0}  {1:N0} bytes' -f $_.FullName, $_.Length }
'zip SHA-256 {0}' -f (Get-FileHash $Zip).Hash
'exe SHA-256 {0}' -f (Get-FileHash (Join-Path $Dist 'PCPorter.exe')).Hash
'files: ' + (($files | ForEach-Object Name | Sort-Object) -join ', ')
