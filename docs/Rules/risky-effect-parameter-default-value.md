# Risky Effect Parameter Default Value

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | risky-effect-parameter-default-value | Warning | — |

## Description

The policy effect is parameterized, but the referenced parameter defaults to an enforcement effect (for example `deny`, `denyAction`, `modify`, `append` or `deployIfNotExists`). This is risky because assignments that don't override the parameter will enforce the policy by default, which the person assigning the policy might not expect.

See [Azure Policy effect basics](https://learn.microsoft.com/azure/governance/policy/concepts/effect-basics) for the behavior of each effect.

## Suggestions

Set the default value of the effect parameter to a non-enforcement effect (`audit`, `auditIfNotExists`, `auditAction` or `disabled`), or drop the default so assignments must choose an effect explicitly.

## Examples

**Violation** -- effect parameter defaulting to the enforcement effect `Deny`:

```json
"effect": {
  "type": "String",
  "defaultValue": "Deny",
  "allowedValues": ["Audit", "Deny", "Disabled"]
}
```

**Correct** -- effect parameter defaulting to the safe effect `Audit`:

```json
"effect": {
  "type": "String",
  "defaultValue": "Audit",
  "allowedValues": ["Audit", "Deny", "Disabled"]
}
```
