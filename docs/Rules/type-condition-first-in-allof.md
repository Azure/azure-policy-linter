# Type Condition First in allOf

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | type-condition-first-in-allof | Warning | — |

## Description

The `type` condition is not the first element in an `allOf` array. By convention, the type check should appear first so that readers immediately see which resource type the policy targets.

## Suggestions

Move the `"field": "type"` condition to the first position in the `allOf` array.

### Violation

```json
"allOf": [
  { "field": "location", "equals": "eastus" },
  { "field": "type", "equals": "Microsoft.Compute/virtualMachines" }
]
```

### Correct

```json
"allOf": [
  { "field": "type", "equals": "Microsoft.Compute/virtualMachines" },
  { "field": "location", "equals": "eastus" }
]
```
