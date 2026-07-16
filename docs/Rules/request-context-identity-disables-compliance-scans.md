# Request Context Identity Disables Compliance Scans

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | request-context-identity-disables-compliance-scans | Warning | default |

## Description

The policy rule references the [`requestContext().identity`](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#policy-functions) function. Compliance scans produce no compliance data for the policy because its compliance state is `NotApplicable`. Enforcement effects such as `Deny`, `DeployIfNotExists`, and `Modify` still run at request time. Using the function may be intentional when only request-time enforcement is needed.

## Suggestions

- If real-time enforcement is the goal and compliance reporting is not needed, no change is required - the `NotApplicable` compliance state is expected.
- If the policy needs compliance data, restructure the rule to evaluate resource fields instead of caller identity, so the policy engine can evaluate it during compliance scans.

## Examples

### Violation

```json
{
  "value": "[tryGet(requestContext().identity, 'idtyp')]",
  "equals": "user"
}
```

### Correct

```json
{
  "field": "tags['owner']",
  "exists": "true"
}
```
