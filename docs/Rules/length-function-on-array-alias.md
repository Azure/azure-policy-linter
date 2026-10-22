# Length Function on Array Alias

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | length-function-on-array-alias | Informational | default |

## Description

The policy asserts the length of an array field using the `length()` template function. A [field count expression](https://learn.microsoft.com/azure/governance/policy/how-to/author-policies-for-arrays#field-count-expressions) returns the same number and is the recommended way to check array length. To count only the array members that match a condition, add a `where` condition.

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
