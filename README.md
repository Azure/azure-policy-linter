# Azure Policy Linter

[![Build](https://github.com/Azure/azure-policy-linter/actions/workflows/build.yml/badge.svg)](https://github.com/Azure/azure-policy-linter/actions/workflows/build.yml)
[![CodeQL](https://github.com/Azure/azure-policy-linter/actions/workflows/codeql.yml/badge.svg)](https://github.com/Azure/azure-policy-linter/actions/workflows/codeql.yml)

Repository for the Azure Policy Linter tool that you can run against your authored policy
definitions to check for rules and best practices.

## Installation

<TODO: Add installation instructions here once the linter is published to a package manager or made available for download.>

## Usage

The linter supports processing single or multiple policy definition files:

### Single file
```
policylinter c:\path\to\policyDefinition.json
```

### Multiple files

- Processes up to 1,000 files in a single run

```
policylinter c:\path\to\policy1.json c:\path\to\policy2.json c:\path\to\policy3.json
```

### With output to JSON file
```
policylinter c:\path\to\policy1.json c:\path\to\policy2.json --output results.json
```
or
```
policylinter c:\path\to\policy1.json -o results.json
```

### Rule documentation

Each rule has a corresponding documentation file in the [docs/Rules/](docs/Rules/) directory.

### Help
```
policylinter --help
```

The linter accepts either a full policy definition resource payload or a JSON containing just the policy definition property bag. When processing multiple files, the linter processes them in parallel for improved performance and provides file-specific results.

## Build and test locally

This repository pins the .NET SDK in `global.json`.

Prerequisite:
- .NET SDK 8.0.418

From the repo root:

```bash
dotnet restore src/dirs.proj
dotnet build src/dirs.proj -c Release
dotnet test src/Tests/PolicyLinter.Tests/PolicyLinter.Tests.csproj -c Release
```

Run the CLI directly from source:

```bash
dotnet run --project src/PolicyLinter.Cli -- path/to/policy.json
```

You can also lint multiple files and write JSON output:

```bash
dotnet run --project src/PolicyLinter.Cli -- path/to/policy1.json path/to/policy2.json -o results.json
```

## Known gaps and issues
- No support for the more obscure leaf expressions like `source`.
- No support for data-plane policies.
- No support for effect details.

## Linter rules

Each linter rule should have a corresponding documentation file [here](docs/Rules/).

## Develop your own rule

The linter discovers rules automatically via reflection by loading all non-abstract implementations
of `ILinterRule` from `PolicyLinter.Core`. You do not need to manually register new rules.

### 1) Add a rule class

Create a new rule class under `src/PolicyLinter.Core/Rules/CommonRules/` and inherit from
`LinterRule<TExpression>` where `TExpression` is the expression type you want to target (for example
`LeafCondition`, `Reference`, or `IfCondition`).

Use existing rules as references, such as:
- `src/PolicyLinter.Core/Rules/CommonRules/LikeNotLikeWithoutWildcards.cs`
- `src/PolicyLinter.Core/Rules/CommonRules/PolicyRuleIfsShouldReferenceOneResourceType.cs`

Skeleton:

```csharp
public sealed class MyNewRule : LinterRule<LeafCondition>
{
	public MyNewRule() : base(
		identifier: "my-new-rule",
		category: Category.BestPractices,
		title: "My New Rule",
		descriptionFormat: "A description with optional placeholders: {0}",
		applyToDerivedTypes: false)
	{
	}

	protected override LinterOutput[] Evaluate(LeafCondition expression, LinterContext context)
	{
		// Return empty when no issue is found.
		// Use CreateError/CreateWarning/CreateInformational to emit results.
		return Array.Empty<LinterOutput>();
	}
}
```

### 2) Add rule documentation

Create a matching markdown file in `docs/Rules/` using the rule identifier as the filename:

`docs/Rules/my-new-rule.md`

Include at least:
- title
- category
- identifier
- severity
- description
- violation example
- corrected example

### 3) Add tests

Add unit tests in `src/Tests/PolicyLinter.Tests/`.

Patterns in this repo:
- rule-focused tests in `RuleTests.cs`
- dedicated test class per rule (for example `PolicyRuleIfsShouldReferenceOneResourceTypeTests.cs`)

Your tests should verify:
- the rule emits output for a violating policy
- no output for compliant input
- identifier/severity/path/line metadata when applicable

### 4) Validate end-to-end

Run:

```bash
dotnet test src/Tests/PolicyLinter.Tests/PolicyLinter.Tests.csproj -c Release
dotnet run --project src/PolicyLinter.Cli -- path/to/your/sample-policy.json
```

## Demo Video

![Azure Policy Linter Demo](./docs/media/PolicyLinterDemo1.gif)

## Contributing

We are not accepting pull requests at this time. However, we welcome all feedback, bug reports,
issues, and suggestions. Please feel free to open an
[issue](https://github.com/Azure/azure-policy-linter/issues) to share your thoughts or report any
problems you encounter. For more information about contributing, please see our [Contributing guidelines](CONTRIBUTIONS.md).

## License

This project is licensed under the MIT License - see [LICENSE](LICENSE) file for details.

## Support

For issues, questions, or suggestions, please open an
[issue](https://github.com/Azure/azure-policy-linter/issues) on GitHub.

## Security

For security issues, please see our [Security policy](SECURITY.md).

## Trademark notice

Trademarks This project may contain trademarks or logos for projects, products, or services.
Authorized use of Microsoft trademarks or logos is subject to and must follow Microsoft’s Trademark
& Brand Guidelines. Use of Microsoft trademarks or logos in modified versions of this project must
not cause confusion or imply Microsoft sponsorship. Any use of third-party trademarks or logos are
subject to those third-party's policies.