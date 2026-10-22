# Numeric Comparison Value in Equality Condition

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | numeric-comparison-value-in-equality-condition | Informational | default |

## Description

The comparison value of an `equals` or `notEquals` condition is an `Integer` or `Float` parameter. Azure Policy converts the parameter value to a string before comparison, so numerically equal values with different string representations can compare as unequal.

## Suggestions

- For numeric equality, use the [`equals()` template function](https://learn.microsoft.com/azure/azure-resource-manager/templates/template-functions-comparison#equals) in a `value` condition with numeric values.

## Examples

`expectedValue` is an `Integer` parameter with value `5`.

### Violation

The condition evaluates to `false` because the comparison value is converted to `"5"`, which differs from `"05"`.

```json
{
  "value": "05",
  "equals": "[parameters('expectedValue')]"
}
```

### Correct

```json
{
  "value": "[equals(int('05'), parameters('expectedValue'))]",
  "equals": true
}
```
