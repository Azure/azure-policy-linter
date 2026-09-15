# All Mode With Indexable Resource Types

| Category | Identifier | Severity | Rule Set |
|---|---|---|---|
| BestPractices | all-mode-with-indexable-resource-types | Informational | default |

## Description

The policy targets resource types that support tags and location but uses `All` mode. The policy still works, but `Indexed` mode is recommended.

## Suggestions

- Consider `Indexed` if that evaluation scope is intended.

See [Resource Manager modes](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/definition-structure-basics#resource-manager-modes).
