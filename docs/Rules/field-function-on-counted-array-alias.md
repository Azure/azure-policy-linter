# Field Function on Counted Array Alias

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | field-function-on-counted-array-alias | Warning | default |

## Description

This rule reports a `where` condition that uses `field()` on the counted alias, which has unintuitive behavior. Replace it with `current()` to read a field of the array member being counted.

The semantics of array aliases (aliases with a `[*]` segment) is "select all values from the array". Referencing an array alias with a `field()` function will always return an array.
In count expressions, the `where` condition is evaluated against each member of the enumerated array. Every iteration "sees" exactly one array member. So any `field()` functions referencing the enumerated array value will return an array containing the value selected from the current array member. If the intention is to access the **value** of the current array member, the policy author needs to write an expression like `first(field(...))`.
This behavior is unintuitive and exists due to the need to preserve backwards compatibility with how `field()` functions work. The `current()` function returns the value of the current array member without the additional complexity and is recommended over `field()` in these cases.

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
