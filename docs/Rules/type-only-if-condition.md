# Type-Only If Condition

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | type-only-if-condition | Informational | default |

## Description

The policy's `if` condition checks only the resource `type`. With the `audit`, `deny`, `modify`, or `append` effect, Azure Policy uses the `type` conditions to decide which resources the policy [applies to](https://learn.microsoft.com/azure/governance/policy/concepts/policy-applicability). Resources of the matching types are reported as non-compliant, and all other resources are not applicable. The policy never reports a resource as compliant.

## Suggestions

- If the policy is meant to flag every resource of the type, no change is needed.
