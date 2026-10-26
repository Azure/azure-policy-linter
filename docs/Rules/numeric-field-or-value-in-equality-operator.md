# Numeric Field or Value in Equality Operator

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | numeric-field-or-value-in-equality-operator | Informational | default |

## Description

An `equals` or `notEquals` condition has a `field` or `value` that is a number. Azure Policy converts the number to a string before it compares the values. As a result, the number `5` equals the string `"5"`.

## Suggestions

- To also compare the value types, use the [`equals()` template function](https://learn.microsoft.com/azure/azure-resource-manager/templates/template-functions-comparison#equals) in a `value` condition.

## Examples

### Violation

If the field value is numeric `5`, the condition evaluates to `true` because the field value is converted to the string `"5"`.

```json
{
  "field": "Microsoft.KeyVault/vaults/softDeleteRetentionInDays",
  "equals": "5"
}
```

### Correct

The `equals()` template function preserves the value types, so numeric field value `5` and string `"5"` compare as unequal.

```json
{
  "value": "[equals(field('Microsoft.KeyVault/vaults/softDeleteRetentionInDays'), '5')]",
  "equals": true
}
```
