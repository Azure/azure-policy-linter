# Field Function on Counted Array Alias

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | field-function-on-counted-array-alias | Warning | default |

## Description

Inside a `count.where` condition, use `current()` to read a field of the array member being counted. This rule reports a `where` condition that uses `field()` on the counted alias instead: [inside `where`, `field()` returns a one-member array](https://learn.microsoft.com/azure/governance/policy/how-to/author-policies-for-arrays#the-field-function-inside-where-conditions) rather than the member's value, so comparing it to a single value never matches.

## Suggestions

- Replace `field('<alias>')` with `current('<alias>')` to compare the current scalar member.

## Examples

### Violation

```json
{
  "count": {
    "field": "Microsoft.Test/widgets/items[*]",
    "where": {
      "value": "[field('Microsoft.Test/widgets/items[*].name')]",
      "equals": "approved"
    }
  },
  "greater": 0
}
```

### Correct

```json
{
  "count": {
    "field": "Microsoft.Test/widgets/items[*]",
    "where": {
      "value": "[current('Microsoft.Test/widgets/items[*].name')]",
      "equals": "approved"
    }
  },
  "greater": 0
}
```
