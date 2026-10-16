# Resource Types Not Supported by Indexed Mode

| Category | Identifier | Severity | Rule Set |
|---|---|---|---|
| ResourceFields | resource-types-not-supported-by-indexed-mode | Error | default |

## Description

The policy uses `Indexed` mode but targets resource types that require `All` mode. Azure Policy skips these resources before evaluating the policy's conditions, so the policy has no effect on them.

Note that subscriptions and resource groups require `All` mode, even when they support tags and location.

## Suggestions

- Set `mode` to `All` to evaluate the referenced type.

See [Resource Manager modes](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/definition-structure-basics#resource-manager-modes).
