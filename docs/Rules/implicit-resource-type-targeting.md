# Implicit Resource Type Targeting

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | implicit-resource-type-targeting | Informational | default |

## Description

This rule reports a policy that targets the fields of a specific resource type (via [field aliases](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-alias)) without an explicit `type` condition. Targeting by alias alone is valid, but it leaves the intended resource types implicit and harder for a reader to determine.

## Suggestions

- Add a `type` condition using `equals` or `in` to make the target resource types clear.

## Examples

### Violation

```json
{
  "field": "Microsoft.Storage/storageAccounts/allowBlobPublicAccess",
  "equals": true
}
```

### Correct

```json
{
  "allOf": [
    {
      "field": "type",
      "equals": "Microsoft.Storage/storageAccounts"
    },
    {
      "field": "Microsoft.Storage/storageAccounts/allowBlobPublicAccess",
      "equals": true
    }
  ]
}
```
