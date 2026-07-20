# Missing Policy Definition Display Name

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | missing-policy-definition-display-name | Informational | default |

## Description

A nonblank [`displayName`](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-basics#display-name-and-description) identifies a policy definition. This rule reports definitions whose `displayName` is missing, empty, or whitespace-only.

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
