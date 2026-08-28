# Field Function on Counted Array Alias

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | field-function-on-counted-array-alias | Warning | default |

## Description

This rule reports a `where` condition that uses `field()` on the counted alias, which has unintuitive behavior. Replace it with `current()` to read a field of the array member being counted.
See: [field-function-inside-where-conditions](https://learn.microsoft.com/azure/governance/policy/how-to/author-policies-for-arrays#the-field-function-inside-where-conditions) for more details on the behavior of `field()` functions inside `where` conditions.

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
