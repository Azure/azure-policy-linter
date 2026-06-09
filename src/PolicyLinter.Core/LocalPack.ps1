param(
    [Parameter(Mandatory=$true)]
    [string]$OutputPath
)

# Get the repository root path (2 levels up from current directory)
$RepoRoot = Split-Path (Split-Path (Get-Location) -Parent) -Parent

# Ensure output directory exists
if (!(Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

Write-Host "Packing NuGet package to: $OutputPath"

# Set EnableLocalization to false or the build gets stuck forever

dotnet pack .\PolicyLinter.Core.csproj `
    -p:NuspecFile=.\PolicyLinter.Core.nuspec `
    -p:NuspecBasePath=$RepoRoot `
    -p:EnableLocalization=false `
    -o $OutputPath

if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to create NuGet package"
    exit $LASTEXITCODE
}
