# Numeric Field or Value in Equality Condition

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | numeric-field-or-value-in-equality-condition | Informational | default |

## Description

An `equals` or `notEquals` condition has a `field` or `value` that resolves to an integer or floating-point number. Azure Policy converts the resolved field or value to a string before comparison, so numerically equal values with different string representations can compare as unequal.

## Suggestions

- For numeric equality, use the [`equals()` template function](https://learn.microsoft.com/azure/azure-resource-manager/templates/template-functions-comparison#equals) in a `value` condition with numeric values.

## Examples

### Violation

The condition evaluates to `false` because numeric `5` is converted to `"5"`, which differs from `"05"`.

```json
{
  "value": 5,
  "equals": "05"
}
```

### Correct

```json
{
  "value": "[equals(5, int('05'))]",
  "equals": true
}
```
