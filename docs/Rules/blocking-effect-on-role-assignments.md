# Blocking Effect on Role Assignments

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | blocking-effect-on-role-assignments | Warning | — |

## Description

The policy uses a blocking [effect](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/effect-basics) (`deny` or `denyAction`) and its `if` targets `Microsoft.Authorization/roleAssignments`, either directly (`equals`, `in`) or through a wildcard `like` over the `Microsoft.Authorization` namespace. Blocking role-assignment creation can prevent just-in-time role activation - for example [Microsoft Entra Privileged Identity Management (PIM)](https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-configure), which activates eligible roles by creating a role assignment. In a deadlock, an administrator who needs to elevate to remove the policy cannot, because elevating itself requires creating a role assignment the policy blocks.

Denying role assignments can be intentional. This finding raises the lockout risk so you can confirm a recovery path exists before assigning the policy.

## Suggestions

- Ensure a standing recovery path that does not depend on creating a new role assignment under the policy's scope - for example persistent Owner or equivalent access at a parent scope above where the policy is assigned, so an administrator can always reach in, remove the assignment, and break the deadlock.
- Validate the recovery path before rollout.

### Violation

```json
{
  "if": {
    "field": "type",
    "equals": "Microsoft.Authorization/roleAssignments"
  },
  "then": {
    "effect": "deny"
  }
}
```
