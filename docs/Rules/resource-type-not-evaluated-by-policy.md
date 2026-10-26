# Resource Type Not Evaluated by Policy

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| ResourceFields | resource-type-not-evaluated-by-policy | Error | default |

## Description

The policy targets a resource type that Azure Policy doesn't evaluate. Requests for this resource type skip policy evaluation, and the policy doesn't report compliance for it, so the policy has no effect on these resources.

The rule checks the resource types listed in the Azure Policy known issues as [exempt from policy evaluation](https://github.com/Azure/azure-policy/blob/master/README.md#resources-that-are-exempt-from-policy-evaluation) or [not supported because of their scale](https://github.com/Azure/azure-policy/blob/master/README.md#resource-types-that-exceed-current-enforcement-and-compliance-scale), for example `Microsoft.Resources/deployments` and `Microsoft.ServiceBus/namespaces/topics`.

## Suggestions

- Target a resource type that Azure Policy evaluates. For example, to control what a deployment creates, target the resource types it deploys instead of `Microsoft.Resources/deployments`.
- For a child resource type that isn't evaluated, check whether its parent resource type has an alias for the setting.

## Examples

### Violation

```json
{
  "if": { "field": "type", "equals": "Microsoft.Resources/deployments" },
  "then": { "effect": "deny" }
}
```
