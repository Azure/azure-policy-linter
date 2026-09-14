# All Mode With Indexable Resource Types

| Category | Identifier | Severity | Rule Set |
|---|---|---|---|
| BestPractices | all-mode-with-indexable-resource-types | Warning | default |

## Description

The policy uses `All` mode and all referenced resource types are known to support tags and location. `Indexed` limits evaluation to types with both capabilities. Resource groups and subscriptions require `All` and are excluded from this suggestion.

## Suggestions

- Consider `Indexed` if that evaluation scope is intended. `All` remains valid.

See [Resource Manager modes](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/definition-structure-basics#resource-manager-modes).
