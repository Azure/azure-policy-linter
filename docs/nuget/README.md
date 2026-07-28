<!-- This README is embedded in the public NuGet packages. Canonical project documentation is in the repository README. -->

# Azure Policy Linter

The Azure Policy Linter inspects Azure Policy definitions for known issues, gotchas, and authoring best practices.

## Install the command-line tool

```console
dotnet tool install --global Microsoft.Azure.Policy.PolicyLinter.Cli
```

Run it against one or more policy definition files:

```console
policylinter <path-to-policy-definition.json>
```

Use `Microsoft.Azure.Policy.PolicyLinter.Core` when integrating the linter as a library.

For usage, rule documentation, source code, and support, see the
[Azure Policy Linter repository](https://github.com/Azure/azure-policy-linter).
