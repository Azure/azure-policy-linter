# Policy Type Must Be Custom

| Category | Identifier |
|----------------|------------------------|
| Misc | policy-type-must-be-custom |

## Description

Change Safety policies must have the `policyType` property set to `Custom`.

The rule ensures that:
- The `policyType` property exists in the policy definition
- The `policyType` value is set to `Custom` (case-insensitive)


### Rule Set

This rule is part of the `ChangeSafety` rule set and is specifically designed for 1P change safety policies. To run this rule, use:

```
policylinter policy.json --rule-set ChangeSafety
```
