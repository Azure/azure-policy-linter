# Missing Policy Definition Description

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | missing-policy-definition-description | Informational | default |

## Description

A nonblank [`description`](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-basics#display-name-and-description) provides context for when a policy definition is used. This rule reports definitions whose `description` is missing, empty, or whitespace-only.

## Suggestions

Add a concise `description` that explains what the policy checks and why.

## Examples

### Violation

```json
"description": "   "
```

### Correct

```json
"description": "Audits storage accounts without secure transfer enabled."
```
