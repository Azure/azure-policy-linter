# Request Context Identity Is Enforcement Only

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | request-context-identity-is-enforcement-only | Warning | default |

## Description

The policy rule references the [`requestContext().identity`](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#policy-functions) function. Compliance scans produce no compliance data for the policy. The policy only performs enforcement actions based on its effect.

## Suggestions

- Acknowledge that identity-dependent enforcement produces no compliance data for the policy.

## Examples

### Violation

```json
{
  "value": "[tryGet(requestContext().identity, 'idtyp')]",
  "equals": "user"
}
```
