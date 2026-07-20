# Field Alias Without Explicit Type Condition

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | field-alias-without-explicit-type-condition | Informational | default |

## Description

A policy can use [field aliases](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-alias) to target resources without an explicit `type` condition, and that is valid. When an `if` condition relies on aliases alone, its intended resource types can be less obvious to readers. This informational rule recommends an explicit positive literal `type` `equals` or `in` condition for clarity; it does not report a [policy applicability](https://learn.microsoft.com/azure/governance/policy/concepts/policy-applicability) error.

## Suggestions

- Add a positive literal `type` condition using `equals` or a nonempty `in` array to make the target resource types clear.
- Leave the policy unchanged when alias-only targeting is intentional and sufficiently clear.

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
