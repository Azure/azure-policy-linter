[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $PackageDirectory,

    [ValidateSet('net8.0', 'net10.0')]
    [string] $ExpectedFramework = 'net10.0'
)

$ErrorActionPreference = 'Stop'
$packageDirectoryPath = (Resolve-Path -LiteralPath $PackageDirectory).ProviderPath
$packages = @(Get-ChildItem -LiteralPath $packageDirectoryPath -Filter '*.nupkg' -File)
if ($packages.Count -eq 0) {
    throw "No packages found in $packageDirectoryPath."
}

Add-Type -AssemblyName System.IO.Compression.FileSystem

function Read-PackageText($Archive, [string] $Path) {
    $entry = $Archive.GetEntry($Path)
    if ($null -eq $entry) {
        throw "Missing package entry: $Path."
    }

    $reader = [System.IO.StreamReader]::new($entry.Open())
    try {
        return $reader.ReadToEnd()
    }
    finally {
        $reader.Dispose()
    }
}

foreach ($package in $packages) {
    $archive = [System.IO.Compression.ZipFile]::OpenRead($package.FullName)
    try {
        $nuspecs = @($archive.Entries | Where-Object { $_.FullName -match '^[^/]+\.nuspec$' })
        if ($nuspecs.Count -ne 1) {
            throw "$($package.Name) must contain exactly one root nuspec."
        }
        [xml] $nuspec = Read-PackageText $archive $nuspecs[0].FullName
        $id = [string] $nuspec.package.metadata.id
        $version = [string] $nuspec.package.metadata.version
        $isTool = $nuspec.SelectNodes("//*[local-name()='packageType' and @name='DotnetTool']").Count -eq 1

        foreach ($framework in @('net8.0', 'net10.0')) {
            if ($isTool) {
                $prefix = "tools/$framework/any/"
                [xml] $settings = Read-PackageText $archive "${prefix}DotnetToolSettings.xml"
                $entryPoint = [string] $settings.DotNetCliTool.Commands.Command.EntryPoint
                $commandName = [string] $settings.DotNetCliTool.Commands.Command.Name
                if ($null -eq $archive.GetEntry("$prefix$entryPoint")) {
                    throw "$id is missing its $framework entry point."
                }
                $runtimeFile = $entryPoint -replace '\.dll$', '.runtimeconfig.json'
                $runtime = (Read-PackageText $archive "$prefix$runtimeFile" | ConvertFrom-Json).runtimeOptions
                $majorVersion = $framework.Substring(3).Split('.')[0]
                if ($runtime.tfm -ne $framework -or
                    $runtime.framework.name -ne 'Microsoft.NETCore.App' -or
                    $runtime.framework.version -ne "$majorVersion.0.0") {
                    throw "$id has an incorrect runtime configuration for $framework."
                }
            }
            elseif (@($archive.Entries | Where-Object { $_.FullName -match "^lib/$([regex]::Escape($framework))/[^/]+\.dll$" }).Count -eq 0) {
                throw "$id has no library assemblies for $framework."
            }
        }
        Write-Host "$id $version contains both framework payloads."
    }
    finally {
        $archive.Dispose()
    }

    if (-not $isTool) {
        continue
    }

    $testDirectory = Join-Path ([System.IO.Path]::GetTempPath()) ('policylinter-package-test-' + [guid]::NewGuid().ToString('N'))
    $previousPackages = $env:NUGET_PACKAGES
    try {
        New-Item -ItemType Directory -Path $testDirectory | Out-Null
        $env:NUGET_PACKAGES = Join-Path $testDirectory 'packages'
        $configPath = Join-Path $testDirectory 'NuGet.config'
        $escapedSource = [System.Security.SecurityElement]::Escape($packageDirectoryPath)
        [System.IO.File]::WriteAllText($configPath, "<configuration><packageSources><clear/><add key='candidate' value='$escapedSource'/></packageSources></configuration>")
        $toolPath = Join-Path $testDirectory 'tools'

        # Omit --framework to verify the SDK's automatic asset selection.
        & dotnet tool install $id --version $version --tool-path $toolPath --configfile $configPath
        if ($LASTEXITCODE -ne 0) {
            throw "Installation failed for $id."
        }

        $storePath = Join-Path (Join-Path (Join-Path $toolPath '.store') $id.ToLowerInvariant()) $version
        $assets = Get-Content -LiteralPath (Join-Path $storePath 'project.assets.json') -Raw | ConvertFrom-Json
        $targets = @($assets.targets.PSObject.Properties)
        if ($targets.Count -ne 1 -or $targets[0].Name -notlike "$ExpectedFramework/*") {
            throw "$id selected an unexpected framework: $($targets.Name -join ', ')."
        }

        $command = Join-Path $toolPath $commandName
        if ($env:OS -eq 'Windows_NT') {
            $command += '.exe'
        }
        $ruleSets = & $command --list-rule-sets
        if ($LASTEXITCODE -ne 0 -or -not ($ruleSets -match 'default:')) {
            throw "$id failed to load its default rule set."
        }

        & $command (Join-Path $testDirectory 'missing.json')
        if ($LASTEXITCODE -eq 0) {
            throw "$id incorrectly succeeded on a missing input file."
        }

        $policyPath = Join-Path $testDirectory 'policy.json'
        $outputPath = Join-Path $testDirectory 'results.json'
        [System.IO.File]::WriteAllText($policyPath, '{"properties":{"displayName":"Package test","mode":"All","policyRule":{"if":{"field":"type","equals":"Microsoft.Storage/storageAccounts"},"then":{"effect":"audit"}}}}')
        & $command $policyPath --output $outputPath
        if ($LASTEXITCODE -ne 0) {
            throw "$id failed to lint a policy."
        }
        $json = Get-Content -LiteralPath $outputPath -Raw
        $results = $json | ConvertFrom-Json
        if ($results.PSObject.Properties.Name -notcontains $policyPath -or
            $json -notmatch '"missing-policy-definition-description"') {
            throw "$id did not produce the expected finding and file-keyed JSON output."
        }

        Write-Host "$id installed and ran using $ExpectedFramework."
    }
    finally {
        $env:NUGET_PACKAGES = $previousPackages
        if (Test-Path -LiteralPath $testDirectory) {
            Remove-Item -LiteralPath $testDirectory -Recurse -Force
        }
    }
}
