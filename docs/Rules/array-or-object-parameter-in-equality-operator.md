# Array or Object Parameter in Equality Operator

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | array-or-object-parameter-in-equality-operator | Error | default |

## Description

An `equals` or `notEquals` condition compares with an `Array` or `Object` parameter. These [operators](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#conditions) need a single value, so the condition is not valid.

## Suggestions

- For an `Array` parameter, use `in` or `notIn` to check whether the value is one of the array items.
- For an `Object` parameter, compare with one property of the object.

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
