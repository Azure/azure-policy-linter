# Numeric Parameter in Equality Operator

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | numeric-parameter-in-equality-operator | Informational | default |

## Description

An `equals` or `notEquals` condition compares with an `Integer` or `Float` parameter. Azure Policy converts the parameter value to a string before it compares the values. As a result, a parameter value of `5` equals the string `"5"`.

## Suggestions

- To also compare the value types, use the [`equals()` template function](https://learn.microsoft.com/azure/azure-resource-manager/templates/template-functions-comparison#equals) in a `value` condition.

## Examples

`expectedValue` is an `Integer` parameter with value `5`, and the `expectedValue` tag contains string `"5"`.

### Violation

The condition evaluates to `true` because the numeric comparison value is converted to the string `"5"`.

```json
{
  "value": "[field('tags.expectedValue')]",
  "equals": "[parameters('expectedValue')]"
}
```

### Correct

The `equals()` template function preserves the value types, so the string tag value and integer parameter compare as unequal.

```json
{
  "value": "[equals(field('tags.expectedValue'), parameters('expectedValue'))]",
  "equals": true
}
```
