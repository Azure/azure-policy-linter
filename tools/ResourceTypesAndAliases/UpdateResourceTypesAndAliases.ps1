# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

#Requires -Version 7.4
#Requires -Modules @{ ModuleName = 'Az.Accounts'; ModuleVersion = '5.3.1' }

[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\..\src\PolicyLinter.Core\ResourceTypesAndAliases')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$context = Get-AzContext
if ($null -eq $context -or $context.Environment.Name -ne 'AzureCloud') {
    throw 'Sign in to Azure public cloud with Connect-AzAccount -Environment AzureCloud before running this script.'
}

$namespaces = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$stagingDirectory = Join-Path $OutputDirectory ".refresh-$([guid]::NewGuid())"
$null = New-Item -ItemType Directory -Path $stagingDirectory -Force
$uri = 'https://management.azure.com/providers?api-version=2021-04-01&$expand=resourceTypes/aliases'
$hasTypes = $false

try {
    do {
        $requestUri = [uri]$uri
        if ($requestUri.Scheme -ne 'https' -or $requestUri.Host -ne 'management.azure.com' -or
            -not $requestUri.IsDefaultPort -or $requestUri.UserInfo) {
            throw "Unexpected providers API URL: $uri"
        }

        $response = Invoke-AzRestMethod -Method GET -Uri $uri -DefaultProfile $context
        if ($response.StatusCode -ne 200) {
            throw "Providers API returned HTTP $($response.StatusCode): $($response.Content)"
        }

        $page = ConvertFrom-Json -InputObject $response.Content -AsHashtable -Depth 100
        if ($page['value'] -isnot [array]) {
            throw 'Providers API response is missing the value array.'
        }

        foreach ($provider in $page.value) {
            $namespace = $provider.namespace
            if ($namespace -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$' -or -not $namespaces.Add($namespace)) {
                throw "Invalid or duplicate provider namespace: $namespace"
            }
            if ($provider['resourceTypes'] -isnot [array]) {
                throw "Provider '$namespace' is missing the resourceTypes array."
            }

            $types = @($provider.resourceTypes | ForEach-Object { [pscustomobject]$_ } |
                Sort-Object -Property resourceType -CaseSensitive -Culture en-US)
            $typeNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($type in $types) {
                if ([string]::IsNullOrWhiteSpace($type.resourceType) -or -not $typeNames.Add($type.resourceType)) {
                    throw "Invalid or duplicate resource type in '$namespace': $($type.resourceType)"
                }
            }
            $hasTypes = $hasTypes -or $types.Count -gt 0
            $documents = @{
                types = @($types | Select-Object capabilities, resourceType)
                aliases = @(
                    foreach ($type in ($types | Where-Object aliases)) {
                        [ordered]@{
                            aliases = @($type.aliases | Sort-Object -Property name -CaseSensitive -Culture en-US)
                            resourceType = $type.resourceType
                        }
                    }
                )
            }

            foreach ($suffix in @('types', 'aliases')) {
                $document = [ordered]@{
                    namespace = $namespace
                    resourceTypes = $documents[$suffix]
                }
                $json = ConvertTo-Json -InputObject $document -Depth 100 -WarningAction Stop
                $json | Set-Content -LiteralPath (Join-Path $stagingDirectory "$namespace.$suffix.json") -Encoding utf8NoBOM
            }
        }
        $uri = $page['nextLink']
    } while ($uri)

    if (-not $hasTypes) {
        throw 'Providers API returned no resource types; existing files were not changed.'
    }

    # Publish only after every page has been fetched and serialized successfully.
    $snapshots = @(Get-ChildItem -LiteralPath $stagingDirectory -File)
    $snapshots | Copy-Item -Destination $OutputDirectory -Force
    Get-ChildItem -LiteralPath $OutputDirectory -File |
        Where-Object {
            ($_.Name -like '*.types.json' -or $_.Name -like '*.aliases.json') -and
            $_.Name -notin $snapshots.Name
        } |
        Remove-Item

    Write-Host "Updated $($namespaces.Count) namespaces in $OutputDirectory"
}
finally {
    Remove-Item -LiteralPath $stagingDirectory -Recurse -Force
}
