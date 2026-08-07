# Field Alias Without Explicit Type Condition

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | field-alias-without-explicit-type-condition | Informational | default |

## Description

This rule reports a policy rule that uses [field aliases](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-alias) to target resources without an explicit `type` condition. Targeting by alias alone is valid, but it leaves the intended resource types implicit and harder for a reader to determine.

## Suggestions

- Add a positive literal `type` condition using `equals` or a nonempty `in` array to make the target resource types clear.

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
