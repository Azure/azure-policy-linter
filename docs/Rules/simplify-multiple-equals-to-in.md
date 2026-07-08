# Simplify Multiple Equals to In

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | simplify-multiple-equals-to-in | Warning | — |

## Description

An `anyOf` contains multiple `equals` conditions on the same field. This can be simplified to a single `in` condition, making the policy shorter and easier to read.

## Suggestions

Replace the `anyOf` with a single condition using the `in` operator and an array of values.

### Violation

```json
"anyOf": [
  { "field": "type", "equals": "Microsoft.Compute/virtualMachines" },
  { "field": "type", "equals": "Microsoft.Storage/storageAccounts" }
]
```

### Correct

```json
{
  "field": "type",
  "in": [
    "Microsoft.Compute/virtualMachines",
    "Microsoft.Storage/storageAccounts"
  ]
}
```
