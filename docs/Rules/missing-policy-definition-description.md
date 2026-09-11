# Missing Policy Definition Description

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | missing-policy-definition-description | Informational | default |

## Description

This rule reports a policy definition whose [`description`](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-basics#display-name-and-description) is missing, empty, or whitespace-only. The `description` helps users understand the policy and troubleshoot its results.

## Suggestions

Add a concise `description` that explains the policy's purpose and logic.

## Examples

### Violation

```json
"description": "   "
```

### Correct

```json
"description": "Audits storage accounts without secure transfer enabled."
```
