# Directly Nested Not Condition

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | directly-nested-not-condition | Informational | default |

## Description

Two directly nested `not` operators negate the same condition twice and are mechanically equivalent to the inner condition. This adds unnecessary nesting without changing the condition's result.

See [logical operators](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#logical-operators) in the Azure Policy definition structure.

## Suggestions

Remove both directly nested `not` operators and use the inner condition directly.

## Examples

### Violation

```json
"not": {
  "not": {
    "field": "location",
    "equals": "eastus"
  }
}
```

### Correct

```json
"field": "location",
"equals": "eastus"
```
