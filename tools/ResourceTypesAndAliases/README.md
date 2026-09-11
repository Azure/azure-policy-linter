# Refresh resource types and aliases

Refreshes the linter's resource types and aliases from Azure public cloud.

## Prerequisites

- PowerShell **7.4+** (`pwsh`).
- **Az.Accounts 5.3.1+**. Azure CLI is not needed.
- An Azure account with access to the tenant's ARM providers API.

Install the module if needed:

```powershell
Install-Module Az.Accounts -MinimumVersion 5.3.1 -Scope CurrentUser
```

## Run

From the repository root, sign in and run:

```powershell
Connect-AzAccount -Environment AzureCloud -Tenant '<tenant-id>'
.\tools\ResourceTypesAndAliases\UpdateResourceTypesAndAliases.ps1
```

Output goes to `src\PolicyLinter.Core\ResourceTypesAndAliases`. To write elsewhere:

```powershell
.\tools\ResourceTypesAndAliases\UpdateResourceTypesAndAliases.ps1 -OutputDirectory .\out\resource-types-and-aliases
```

## Output

Each namespace gets two files:

| File | Contents |
| --- | --- |
| `<namespace>.types.json` | Resource type names and capabilities; `null` means unknown. |
| `<namespace>.aliases.json` | Types with aliases, preserving alias details from ARM. |

The script reads all pages of the [tenant-level providers API](https://learn.microsoft.com/en-us/rest/api/resources/providers/list-at-tenant-scope?view=rest-resources-2021-04-01) with alias expansion. Results reflect the signed-in tenant's visibility; no Azure resources are changed.

Files are staged before replacement. A successful refresh removes obsolete `*.types.json` and `*.aliases.json` files, so use a dedicated output directory. Review the diff before committing; do not edit generated JSON.
