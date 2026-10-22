# Invalid Effect Parameter Value

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | invalid-effect-parameter-value | Error | default |

## Description

The policy's effect is set by a parameter, and the parameter's `allowedValues` or `defaultValue` contains a value that isn't a policy [effect](https://learn.microsoft.com/azure/governance/policy/concepts/effect-basics). Azure Policy rejects a policy definition with such a value. This is usually a typo, or a property value such as `Enabled` used by mistake. Policies with a Resource Provider mode aren't checked.

## Suggestions

- Correct the value to the intended effect, or remove it.
- Use only effects that work with the policy rule. See [interchanging effects](https://learn.microsoft.com/azure/governance/policy/concepts/effect-basics#interchanging-effects).

## Examples

### Violation

```json
"effect": {
  "type": "String",
  "allowedValues": ["Audit", "Deny", "Enabled"],
  "defaultValue": "Audit"
}
```

`Enabled` is not an effect.

### Correct

```json
"effect": {
  "type": "String",
  "allowedValues": ["Audit", "Deny", "Disabled"],
  "defaultValue": "Audit"
}
```
