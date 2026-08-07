# Implicit Array Enumeration

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | implicit-array-enumeration | Informational | default |

## Description

This rule reports a `field` condition targeting the members of an array alias (i.e. an alias containing `[*]`). The condition will perform an implicit "allOf" evaluation, applying the condition to each array member. Use `count` expression instead, which provides a more deliberate and capable mechanism to apply conditions to array members. For more details, see [field count expressions](https://learn.microsoft.com/en-us/azure/governance/policy/how-to/author-policies-for-arrays#field-count-expressions).

## Suggestions

Use a field `count` expression.

## Examples

### Violation

```json
{
  "field": "Microsoft.Test/testResource/items[*].name",
  "equals": "approved"
}
```

### Correct

```json
{
  "count": {
    "field": "Microsoft.Test/testResource/items[*]",
    "where": {
      "field": "Microsoft.Test/testResource/items[*].name",
      "notEquals": "approved"
    }
  },
  "equals": 0
}
```
