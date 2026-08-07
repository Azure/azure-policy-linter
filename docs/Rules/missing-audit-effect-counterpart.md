# Missing Audit Effect Counterpart

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | missing-audit-effect-counterpart | Informational | default |

## Description

This rule reports a policy whose effect is parameterized, but whose allowed effects are enforcement effects only. An assignment can then only block or change requests. Offering the matching audit effect as well lets the policy be assigned with an audit effect first, to see what it would have blocked before it starts enforcing.

The counterparts are `deny`, `modify`, and `append` -> `audit`, `deployIfNotExists` -> `auditIfNotExists`, and `denyAction` -> `auditAction`. See [interchanging effects](https://learn.microsoft.com/azure/governance/policy/concepts/effect-basics#interchanging-effects).

## Suggestions

Add the missing audit counterpart to the effect parameter's `allowedValues`.

## Examples

### Violation

```json
"allowedValues": ["Deny"]
```

### Correct

```json
"allowedValues": ["Audit", "Deny"]
```
