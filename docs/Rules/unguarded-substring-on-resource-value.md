# Unguarded Substring on Resource Value

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | unguarded-substring-on-resource-value | Error | default |

## Description

The `substring` function produces an evaluation error when the requested range exceeds the length of its input. For example, `substring(field('name'), 0, 3)` errors when the resource name is shorter than three characters, and a [template evaluation error makes the policy act as deny](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#avoiding-template-failures). This rule flags direct three-argument `substring` calls on resource values with fixed bounds that require a positive minimum input length.

## Suggestions

Guard the `substring` call with `if()` and `length()` so it is evaluated only when the resource value is long enough for the requested range.

## Examples

### Violation

```json
{
  "value": "[substring(field('name'), 0, 3)]",
  "equals": "abc"
}
```

### Correct

```json
{
  "value": "[if(greaterOrEquals(length(field('name')), 3), substring(field('name'), 0, 3), field('name'))]",
  "equals": "abc"
}
```
