# Invalid Template Function Argument

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | invalid-template-function-argument | Error | default |

## Description

This rule reports a [template function](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#policy-functions) call that fails with the values written in the policy. The values are literals, or come from a parameter's `defaultValue` or `allowedValues`. Evaluation fails whenever the policy uses those values, and [a failed evaluation is an implicit deny](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#avoiding-template-failures).

Common causes:

| Function | Fails when |
|---|---|
| `int()`, `float()`, `bool()` | The value can't be converted, for example `int('ten')`. |
| `addDays()` | The date isn't in the Universal ISO 8601 format, or the number of days isn't an integer. |
| `ipRangeContains()` | A value isn't an IP address, a CIDR range, or a start and end range, for example `AzureCloud`. |
| `json()`, `base64ToString()`, `base64ToJson()` | The value isn't valid JSON or base64. |
| `div()`, `mod()` | An argument isn't an integer, or the divisor is zero. |
| `min()`, `max()` | The array is empty, or a value isn't a number. |
| `substring()` | The range is negative or runs past the end of the string. |
| `replace()` | The string to replace is empty. |
| `range()` | The count is less than 0 or greater than 10000. |
| `padLeft()` | The total length isn't from 1 to 16, or the padding character isn't a single character. |

## Suggestions

- Fix the value in the call.
- For a parameter, fix its `defaultValue` and `allowedValues`, and declare it with the type the function expects (for example `Integer` for `int()` and `div()`).
- If a value that fails is valid for the parameter, check it with `if()` before the call.

## Examples

### Violation

```json
"parameters": {
  "maxCount": {
    "type": "String",
    "allowedValues": [ "5", "ten" ]
  }
}
```

```json
{
  "value": "[int(parameters('maxCount'))]",
  "less": 5
}
```

### Correct

```json
"parameters": {
  "maxCount": {
    "type": "Integer",
    "allowedValues": [ 5, 10 ]
  }
}
```

```json
{
  "value": "[parameters('maxCount')]",
  "less": 5
}
```
