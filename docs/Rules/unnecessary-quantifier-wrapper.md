# Unnecessary allOf/anyOf Wrapper

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | unnecessary-quantifier-wrapper | Warning | default |

## Description

An `allOf` or `anyOf` contains only a single child expression. The wrapper is redundant and adds unnecessary nesting to the policy definition.

## Suggestions

Remove the `allOf` or `anyOf` wrapper and use the inner expression directly.

### Violation

```json
"if": {
  "allOf": [
    {
      "field": "type",
      "equals": "Microsoft.Compute/virtualMachines"
    }
  ]
}
```

### Correct

```json
"if": {
  "field": "type",
  "equals": "Microsoft.Compute/virtualMachines"
}
```
