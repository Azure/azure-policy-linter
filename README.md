# Azure Policy Linter

[![Build](https://github.com/Azure/azure-policy-linter/actions/workflows/build.yml/badge.svg)](https://github.com/Azure/azure-policy-linter/actions/workflows/build.yml)
[![CodeQL](https://github.com/Azure/azure-policy-linter/actions/workflows/codeql.yml/badge.svg)](https://github.com/Azure/azure-policy-linter/actions/workflows/codeql.yml)

Repository for the Azure Policy Linter, a tool built by the Azure Policy team to improve the quality of [Azure Policy Definitions](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/definition-structure-basics) by surfacing known issues, gotchas and best practices.

## Background

[Azure Policy](https://learn.microsoft.com/en-us/azure/governance/policy/overview) allows users to define, assign and manage policies that apply to their Azure resources.
Policies can define various [effects](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/effect-basics) to determine what action the policy should take when a non-compliant resource is being created/updated. Policies are also evaluated periodically against all existing resources to produce [compliance data](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/compliance-states).

Writing a good policy requires a deep knowledge of the capabilities of the policy language, policy effects, as well as the API of the resources each policy is targeting. This knowledge is scattered across multiple sources, and in cases such as resource API behavior, might not be documented at all.
The linter project is meant to codify this knowledge and surface it as actionable error/warning/informational findings on a specific policy definition.

## Installation

> Currently (6/2026), installation requires [building the linter from source](#building-from-source). The Azure Policy team is working on publishing it to [nuget.org](https://nuget.org) as a dotnet tool in the near future.

## Building from source

Until a published package is available, building from source is the only way to run the linter. See [CONTRIBUTIONS.md](CONTRIBUTIONS.md#local-build-pack-and-run) for build, run, and pack instructions.

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

### Rule sets

The linter organizes rules into rule sets for different linting scenarios. By default, the linter uses the "default" rule set which includes general-purpose rules.

List available rule sets:
```
policylinter --list-rule-sets
```

Apply a specific rule set:
```
policylinter policy.json --rule-set <RuleSetName>
```

Apply multiple rule sets:
```
policylinter policy.json --rule-set <RuleSetName> --rule-set default
```

### Rule documentation

Each rule has a corresponding documentation file in the [docs/Rules/](docs/Rules/) directory.

### Help
```
policylinter --help
```

The linter accepts either a full policy definition resource payload or a JSON containing just the policy definition property bag. When processing multiple files, the linter processes them in parallel for improved performance and provides file-specific results.

## Known gaps and issues
- No support for the more obscure leaf expressions like `source`.
- No support for data-plane policies.
- No support for effect details.

## Documentation

- [docs/linter-rule-design.md](docs/linter-rule-design.md) - what a good linter rule should be: scope, severity, naming, and description conventions.
- [docs/linter-architecture.md](docs/linter-architecture.md) - how the linter works in code and what it takes to add a rule.
- [docs/Rules/](docs/Rules/) - per-rule documentation, one file per rule.

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
Authorized use of Microsoft trademarks or logos is subject to and must follow Microsoft's Trademark
& Brand Guidelines. Use of Microsoft trademarks or logos in modified versions of this project must
not cause confusion or imply Microsoft sponsorship. Any use of third-party trademarks or logos are
subject to those third-party's policies.
