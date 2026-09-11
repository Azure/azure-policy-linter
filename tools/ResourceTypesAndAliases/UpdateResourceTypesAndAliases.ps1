# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

#Requires -Version 7.4
#Requires -Modules @{ ModuleName = 'Az.Accounts'; ModuleVersion = '5.3.1' }

<#
.SYNOPSIS
Refreshes public-cloud resource types and aliases from Azure Resource Manager.
.PARAMETER OutputDirectory
Directory for generated namespace files. Defaults to PolicyLinter.Core\ResourceTypesAndAliases.
#>
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
$generatedFiles = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$OutputDirectory = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputDirectory)
$stagingDirectory = Join-Path $OutputDirectory ".refresh-$([guid]::NewGuid())"
$null = New-Item -ItemType Directory -Path $stagingDirectory -Force
$uri = 'https://management.azure.com/providers?api-version=2021-04-01&$expand=resourceTypes/aliases'
$typeCount = 0
$aliasCount = 0

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

            $types = [System.Collections.Generic.List[object]]::new()
            $aliasTypes = [System.Collections.Generic.List[object]]::new()
            $typeNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

            foreach ($type in ($provider.resourceTypes | Sort-Object -Property resourceType -CaseSensitive -Culture en-US)) {
                if ([string]::IsNullOrWhiteSpace($type.resourceType) -or -not $typeNames.Add($type.resourceType)) {
                    throw "Invalid or duplicate resource type in '$namespace': $($type.resourceType)"
                }

                $types.Add([ordered]@{
                    capabilities = $type['capabilities']
                    resourceType = $type.resourceType
                })

                $aliases = @(
                    $type['aliases'] | Where-Object { $null -ne $_ } |
                        Sort-Object -Property name -CaseSensitive -Culture en-US |
                        ForEach-Object {
                            [ordered]@{
                                defaultMetadata = $_['defaultMetadata']
                                name = $_.name
                                defaultPath = $_['defaultPath']
                                paths = @($_['paths'] | Where-Object { $null -ne $_ })
                            }
                        }
                )
                if ($aliases.Count -gt 0) {
                    $aliasTypes.Add([ordered]@{
                        aliases = $aliases
                        resourceType = $type.resourceType
                    })
                }
                $aliasCount += $aliases.Count
            }
            $typeCount += $types.Count

            foreach ($entry in @(
                @{ Suffix = 'types'; ResourceTypes = $types.ToArray() },
                @{ Suffix = 'aliases'; ResourceTypes = $aliasTypes.ToArray() }
            )) {
                $fileName = "$namespace.$($entry.Suffix).json"
                $document = [ordered]@{
                    namespace = $namespace
                    resourceTypes = $entry.ResourceTypes
                }
                $json = ConvertTo-Json -InputObject $document -Depth 100 -WarningAction Stop
                [System.IO.File]::WriteAllText(
                    (Join-Path $stagingDirectory $fileName),
                    $json.Replace("`r`n", "`n") + "`n",
                    [System.Text.UTF8Encoding]::new($false))
                $null = $generatedFiles.Add($fileName)
            }
        }
        $uri = $page['nextLink']
    } while ($uri)

    if ($typeCount -eq 0) {
        throw 'Providers API returned no resource types; existing files were not changed.'
    }

    # Publish only after every page has been fetched and serialized successfully.
    Get-ChildItem -LiteralPath $stagingDirectory -File |
        Copy-Item -Destination $OutputDirectory -Force
    Get-ChildItem -LiteralPath $OutputDirectory -File |
        Where-Object {
            ($_.Name -like '*.types.json' -or $_.Name -like '*.aliases.json') -and
            -not $generatedFiles.Contains($_.Name)
        } |
        Remove-Item

    Write-Host "Generated $($namespaces.Count) namespaces, $typeCount resource types, and $aliasCount aliases in $OutputDirectory"
}
finally {
    Remove-Item -LiteralPath $stagingDirectory -Recurse -Force
}
