# Numeric Comparison Value in Equality Condition

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | numeric-comparison-value-in-equality-condition | Informational | default |

## Description

The comparison value of an `equals` or `notEquals` condition is an `Integer` or `Float` parameter. Azure Policy converts the parameter value to a string before comparison, so a string and a number with the same text can compare as equal. Numeric formatting can also affect the result.

## Suggestions

- For type-sensitive equality, use the [`equals()` template function](https://learn.microsoft.com/azure/azure-resource-manager/templates/template-functions-comparison#equals) in a `value` condition.

## Examples

`expectedValue` is an `Integer` parameter with value `5`.

### Violation

The condition evaluates to `true` because the numeric comparison value is converted to the string `"5"`.

```json
{
  "value": "5",
  "equals": "[parameters('expectedValue')]"
}
```

### Correct

The `equals()` template function preserves the value types, so string `"5"` and integer `5` compare as unequal.

```json
{
  "value": "[equals('5', parameters('expectedValue'))]",
  "equals": true
}
```
