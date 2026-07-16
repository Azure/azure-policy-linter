# Blocking Effect on Role Assignments

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | blocking-effect-on-role-assignments | Warning | — |

## Description

The policy uses a blocking [effect](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/effect-basics) (`deny`) - specified as a literal, or as a parameterized effect that can take a blocking value (a value in its `allowedValues`, or any value when no `allowedValues` constrain it) - and its `if` targets `Microsoft.Authorization/roleAssignments` or `Microsoft.Authorization/roleAssignmentScheduleRequests` (the type through which [Privileged Identity Management activation](https://learn.microsoft.com/en-us/azure/role-based-access-control/pim-integration#how-to-limit-the-creation-of-eligible-or-time-bound-role-assignments) is submitted), either directly (`equals`, `in`) or through a `like` value that matches one of those types. Denying creation of role assignments prevents granting access under the policy's scope, and denying the schedule-request type prevents activating eligible access. In a deadlock, an administrator who needs to grant themselves (or someone else) the access required to remove the policy cannot, because granting or activating that access is blocked by the policy.

Denying role assignments can be intentional. This finding raises the lockout risk so you can confirm a recovery path exists before assigning the policy.

## Suggestions

- Ensure a standing recovery path that does not depend on creating a new role assignment under the policy's scope - for example persistent Owner or equivalent access at a parent scope above where the policy is assigned, so an administrator can always reach in, remove the assignment, and break the deadlock.
- Validate the recovery path before rollout.

## Examples

**Violation** -- `deny` on the role-assignment type:

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

**Correct** -- the same type condition with a non-blocking `audit` effect:

```json
{
  "if": {
    "field": "type",
    "equals": "Microsoft.Authorization/roleAssignments"
  },
  "then": {
    "effect": "audit"
  }
}
```
