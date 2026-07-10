# Simplify Multiple NotEquals to NotIn

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | simplify-multiple-notequals-to-notin | Informational | — |

## Description

An `allOf` contains multiple [`notEquals`](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#conditions) conditions on the same field. This can be simplified to a single [`notIn`](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#conditions) condition, making the policy shorter and easier to read.

## Suggestions

Replace the grouped `notEquals` conditions with a single condition using the `notIn` operator and an array of values. Leave any other members of the `allOf` in place.

### Violation

```json
"allOf": [
  { "field": "type", "notEquals": "Microsoft.Compute/virtualMachines" },
  { "field": "type", "notEquals": "Microsoft.Storage/storageAccounts" }
]
```

### Correct

```json
"allOf": [
  {
    "field": "type",
    "notIn": [
      "Microsoft.Compute/virtualMachines",
      "Microsoft.Storage/storageAccounts"
    ]
  }
]
```
