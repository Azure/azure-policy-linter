# Refresh resource types and aliases

`UpdateResourceTypesAndAliases.ps1` generates the linter's public-cloud resource type and alias snapshots.
This is repository tooling, outside the source projects and not included in the NuGet packages.

## Prerequisites

- PowerShell **7.4 or later** (`pwsh`), not Windows PowerShell 5.1.
- **Az.Accounts 5.3.1 or later**, providing `Connect-AzAccount`, `Get-AzContext`, and `Invoke-AzRestMethod`. Azure CLI and the full Az module are not required.
- An authenticated **AzureCloud** PowerShell context for a tenant where your account can call the ARM providers API.
- HTTPS access to `management.azure.com` and the Microsoft Entra sign-in endpoints.
- Write access to the output directory.

Install the module if needed, then sign in from PowerShell:

```powershell
Install-Module Az.Accounts -MinimumVersion 5.3.1 -Scope CurrentUser
Connect-AzAccount -Environment AzureCloud -Tenant '<tenant-id>'
```

The script does not install modules, sign in, change clouds, or modify Azure resources.

## Generate

From the repository root, in the same PowerShell session:

```powershell
.\tools\ResourceTypesAndAliases\UpdateResourceTypesAndAliases.ps1
```

The default output is `src\PolicyLinter.Core\ResourceTypesAndAliases`, independent of the working directory. To inspect a candidate separately:

```powershell
.\tools\ResourceTypesAndAliases\UpdateResourceTypesAndAliases.ps1 -OutputDirectory .\out\resource-types-and-aliases
```

The script calls the [tenant-level providers API](https://learn.microsoft.com/en-us/rest/api/resources/providers/list-at-tenant-scope?view=rest-resources-2021-04-01) with `api-version=2021-04-01` and `$expand=resourceTypes/aliases`, following all pages. Results reflect the signed-in tenant's visibility.

## Output

Each namespace gets two files, retaining the existing `namespace` / `resourceTypes` structure:

| File | Contents |
| --- | --- |
| `<namespace>.types.json` | All resource type names and their original capabilities strings. Missing capabilities remain `null`. |
| `<namespace>.aliases.json` | Types with aliases, including alias names, default paths, default metadata, and version-specific paths and metadata. |

Resource types and aliases are sorted by name using a fixed culture. Files use UTF-8 without a BOM, two-space JSON indentation, and LF line endings.

All pages are fetched and files staged before existing snapshots are overwritten. Obsolete `*.types.json` and `*.aliases.json` files are removed from the output directory on a successful refresh; use a directory dedicated to generated metadata. Review the generated diff before committing. Do not edit the JSON by hand.
