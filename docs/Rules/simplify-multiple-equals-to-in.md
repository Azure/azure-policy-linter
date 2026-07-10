# Simplify Multiple Equals to In

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | simplify-multiple-equals-to-in | Informational | — |

## Description

An `anyOf` contains multiple [`equals`](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#conditions) conditions on the same field. This can be simplified to a single [`in`](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#conditions) condition, making the policy shorter and easier to read.

## Suggestions

Replace only the grouped `equals` conditions with a single condition using the `in` operator and an array of values. Leave any other members of the `anyOf` in place.

### Violation

```json
"anyOf": [
  { "field": "type", "equals": "Microsoft.Compute/virtualMachines" },
  { "field": "type", "equals": "Microsoft.Storage/storageAccounts" }
]
```

### Correct

```json
"anyOf": [
  {
    "field": "type",
    "in": [
      "Microsoft.Compute/virtualMachines",
      "Microsoft.Storage/storageAccounts"
    ]
  }
]
```
