# Missing Policy Definition Display Name

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | missing-policy-definition-display-name | Informational | default |

## Description

This rule reports a policy definition whose [`displayName`](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-basics#display-name-and-description) is missing, empty, or whitespace-only. The `displayName` is what identifies the definition wherever policies are listed.

## Suggestions

Add a concise `displayName` that identifies the policy definition.

## Examples

### Violation

```json
"displayName": "   "
```

### Correct

```json
"displayName": "Audit storage accounts"
```
