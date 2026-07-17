# Request Context Identity Is Enforcement Only

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | request-context-identity-is-enforcement-only | Warning | default |

## Description

The policy rule references the [`requestContext().identity`](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#policy-functions) function. Compliance scans produce no compliance data for the policy because its compliance state is `NotApplicable`. Enforcement effects such as `Deny`, `DeployIfNotExists`, and `Modify` still run at request time.

## Suggestions

- Accept that identity-dependent enforcement produces no compliance data for the policy.

## Examples

### Violation

```json
{
  "value": "[tryGet(requestContext().identity, 'idtyp')]",
  "equals": "user"
}
```
