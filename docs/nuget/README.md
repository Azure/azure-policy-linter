<!-- This README is embedded in the public NuGet packages. Canonical project documentation is in the repository README. -->

# Azure Policy Linter

The Azure Policy Linter inspects Azure Policy definitions for known issues, gotchas, and authoring best practices.

## Install the command-line tool

The library and CLI packages include .NET 8 and .NET 10 assets. Use the .NET 10 SDK and runtime
for supported execution. The .NET 8 assets preserve compatibility for existing consumers;
.NET 8 itself is out of support.

```console
dotnet tool install --global Microsoft.Azure.Policy.PolicyLinter.Cli
```

Run it against one or more policy definition files:

```console
policylinter <path-to-policy-definition.json>
```

Use `Microsoft.Azure.Policy.PolicyLinter.Core` when integrating the linter as a library.
NuGet selects the compatible library asset for the consuming project's target framework.

For usage, rule documentation, source code, and support, see the
[Azure Policy Linter repository](https://github.com/Azure/azure-policy-linter).
