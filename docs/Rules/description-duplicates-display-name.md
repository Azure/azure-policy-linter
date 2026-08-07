# Description Duplicates Display Name

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | description-duplicates-display-name | Informational | default |

## Description

This rule reports a nonblank `description` that repeats the [`displayName`](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-basics#display-name-and-description) without adding context. The `displayName` identifies the policy definition, while `description` explains what the policy checks and why.

## Suggestions

Replace the description with a concise explanation of what the policy checks and why.

## Examples

### Violation

```json
{
  "displayName": "Audit storage accounts",
  "description": "Audit storage accounts"
}
```

### Correct

```json
{
  "displayName": "Audit storage accounts",
  "description": "Audits whether storage accounts allow public network access."
}
```
