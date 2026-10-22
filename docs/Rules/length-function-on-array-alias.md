# Length Function on Array Alias

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | length-function-on-array-alias | Informational | default |

## Description

A `value` condition uses `length()` to get the number of members of an array alias (an alias with `[*]`) and compares it to a number. A [field count expression](https://learn.microsoft.com/azure/governance/policy/how-to/author-policies-for-arrays#field-count-expressions) without a `where` condition returns the same number and is the standard way to check the number of array members. A `count` is also easier to change later, for example to count only the members that meet a condition.

## Suggestions

Replace the `value` condition with a field `count` expression over the same array alias, and keep the operator and the number.

## Examples

### Violation

```json
{
  "value": "[length(field('Microsoft.Test/resourceType/stringArray[*]'))]",
  "greater": 0
}
```

### Correct

```json
{
  "count": {
    "field": "Microsoft.Test/resourceType/stringArray[*]"
  },
  "greater": 0
}
```
