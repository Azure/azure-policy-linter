# Request Context Identity Disables Compliance Scans

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | request-context-identity-disables-compliance-scans | Warning | default |

## Description

The policy rule references the [`requestContext().identity`](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#policy-functions) function. When a policy uses this function, the policy engine marks the policy as `NotApplicable` for compliance evaluation, so it never appears in compliance results. Enforcement effects such as `Deny`, `DeployIfNotExists`, and `Modify` still run at request time. Using the function may be intentional (real-time enforcement on create/update operations rather than compliance reporting); the finding surfaces the consequence so empty compliance results are not a surprise.

## Suggestions

- If real-time enforcement is the goal and compliance reporting is not needed, no change is required - the `NotApplicable` compliance state is expected.
- If the policy needs to appear in compliance results, restructure the rule to evaluate resource fields instead of caller identity, so the policy engine can evaluate it during compliance scans.

### Violation

```json
{
  "value": "[tryGet(requestContext().identity, 'idtyp')]",
  "equals": "user"
}
```
