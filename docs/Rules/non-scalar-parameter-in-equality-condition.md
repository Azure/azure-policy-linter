# Non-Scalar Parameter in Equality Condition

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | non-scalar-parameter-in-equality-condition | Error | default |

## Description

An `equals` or `notEquals` condition uses an `array` or `object` parameter as its comparison value. These [condition operators](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#conditions) accept scalar comparison values, not whole arrays or objects. Azure rejects the policy definition rather than comparing the contents of the array or object.

## Suggestions

- If the intent is to check whether a field value is contained in an array parameter, use `in` or `notIn`.
- For a comparison of complete arrays or objects, use the [`equals()` template function](https://learn.microsoft.com/azure/azure-resource-manager/templates/template-functions-comparison#equals) in a `value` condition.

## Examples

`allowedEnvironments` is an array parameter.

### Violation

```json
{
  "field": "tags.environment",
  "equals": "[parameters('allowedEnvironments')]"
}
```

### Correct

```json
{
  "field": "tags.environment",
  "in": "[parameters('allowedEnvironments')]"
}
```
