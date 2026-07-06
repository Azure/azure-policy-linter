# Simplify Multiple NotEquals to NotIn

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | simplify-multiple-notequals-to-notin | Warning | — |

## Description

An `allOf` contains multiple `notEquals` conditions on the same field. This can be simplified to a single `notIn` condition, making the policy shorter and easier to read.

## Suggestions

Replace the `allOf` with a single condition using the `notIn` operator and an array of values.

### Violation

```json
"allOf": [
  { "field": "type", "notEquals": "Microsoft.Compute/virtualMachines" },
  { "field": "type", "notEquals": "Microsoft.Storage/storageAccounts" }
]
```

### Correct

```json
{
  "field": "type",
  "notIn": [
    "Microsoft.Compute/virtualMachines",
    "Microsoft.Storage/storageAccounts"
  ]
}
```
