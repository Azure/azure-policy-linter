# Indexed Mode With Non-Indexable Resource Types

| Category | Identifier | Severity | Rule Set |
|---|---|---|---|
| ResourceFields | indexed-mode-with-non-indexable-resource-types | Error | default |

## Description

`Indexed` mode causes the evaluation engine to skip the targeted non-indexable resource types. The policy therefore cannot audit or enforce its requirements on them, which is why this finding is an error. An omitted or null mode also uses `Indexed` semantics.

## Suggestions

- Set `mode` to `All` to evaluate the referenced type.

See [Resource Manager modes](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/definition-structure-basics#resource-manager-modes).
