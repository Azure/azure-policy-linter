# Equality Check on Floating-Point Value

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | equality-check-on-floating-point-value | Informational | default |

## Description

An `equals` or `notEquals` condition compares a floating-point literal or `Float` parameter as a string rather than comparing numbers. Numeric formatting can therefore affect the result. For example, `5.0` can be converted to `"5"` for comparison.

## Suggestions

- For numeric equality, use the [`equals()` template function](https://learn.microsoft.com/azure/azure-resource-manager/templates/template-functions-comparison#equals) in a `value` condition with numeric operands.

## Examples

### Violation

The condition below evaluates to `false` because the numeric value `5.0` is converted to the string `"5"`, which differs from `"5.0"`.

```json
{
  "value": 5.0,
  "equals": "5.0"
}
```

### Correct

The `equals()` template function compares the values as numbers.

```json
{
  "value": "[equals(float('5.0'), float('5.0'))]",
  "equals": true
}
```
