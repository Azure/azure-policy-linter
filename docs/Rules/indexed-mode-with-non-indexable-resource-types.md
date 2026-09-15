# Indexed Mode With Non-Indexable Resource Types

| Category | Identifier | Severity | Rule Set |
|---|---|---|---|
| ResourceFields | indexed-mode-with-non-indexable-resource-types | Error | default |

## Description

The policy targets resource types that `Indexed` mode skips: types without both tags and location support, resource groups, or subscriptions.

## Suggestions

- Set `mode` to `All` to evaluate the referenced type.

See [Resource Manager modes](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/definition-structure-basics#resource-manager-modes).
