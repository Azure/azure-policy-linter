# Missing Audit Effect Counterpart

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | missing-audit-effect-counterpart | Informational | default |

## Description

This rule reports a String parameter referenced directly by `then.effect` when its `allowedValues` contains an enforcement effect without the corresponding audit effect. The mappings are `deny`, `modify`, or `append` -> `audit`; `deployIfNotExists` -> `auditIfNotExists`; and `denyAction` -> `auditAction`. Including the counterparts lets assignments use non-enforcing behavior without changing the policy definition.

See [interchanging effects](https://learn.microsoft.com/azure/governance/policy/concepts/effect-basics#interchanging-effects) for guidance on which effects can be interchanged.

## Suggestions

Add each missing audit counterpart to the effect parameter's `allowedValues`.

## Examples

### Violation

```json
"allowedValues": ["Deny"]
```

### Correct

```json
"allowedValues": ["Audit", "Deny"]
```
