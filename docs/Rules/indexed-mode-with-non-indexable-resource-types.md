# Indexed Mode With Non-Indexable Resource Types

| Category | Identifier | Severity | Rule Set |
|---|---|---|---|
| ResourceFields | indexed-mode-with-non-indexable-resource-types | Error | default |

## Description

The policy references a resource type that is not evaluated in `Indexed` mode. This includes types without both tags and location support, resource groups, and subscriptions. An omitted or null mode also uses `Indexed` semantics.

## Suggestions

- Set `mode` to `All` to evaluate the referenced type.

See [Resource Manager modes](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/definition-structure-basics#resource-manager-modes).
