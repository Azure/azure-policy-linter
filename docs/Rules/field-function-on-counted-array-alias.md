# Field Function on Counted Array Alias

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | field-function-on-counted-array-alias | Warning | default |

## Description

Inside a field `count.where` condition, [`field()` on the counted array alias](https://learn.microsoft.com/azure/governance/policy/how-to/author-policies-for-arrays#the-field-function-inside-where-conditions) returns a one-member array, while `current()` returns the current scalar value. A scalar comparison against that one-member array does not compare the member being counted, so the `where` condition does not filter as intended.

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
