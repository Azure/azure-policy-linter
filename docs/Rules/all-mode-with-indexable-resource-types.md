# All Mode With Indexable Resource Types

| Category | Identifier | Severity | Rule Set |
|---|---|---|---|
| BestPractices | all-mode-with-indexable-resource-types | Informational | default |

## Description

The policy uses `All` mode for resource types that support tags and location. The policy still works; `Indexed` would limit evaluation to types that support both.

## Suggestions

- Consider `Indexed` if that evaluation scope is intended.

See [Resource Manager modes](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/definition-structure-basics#resource-manager-modes).
