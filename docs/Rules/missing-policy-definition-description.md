# Missing Policy Definition Description

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | missing-policy-definition-description | Informational | default |

## Description

This rule reports a policy definition whose [`description`](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-basics#display-name-and-description) is missing, empty, or whitespace-only. The `description` gives readers the context for when the definition should be used.

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
