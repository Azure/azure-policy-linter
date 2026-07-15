# Equality Check on Numeric Field

| Category | Identifier | Severity | Rule Set |
|----------------|---------------------------------|---------------|----------|
| ResourceFields | equality-check-on-numeric-field | Informational | default |

## Description

A `field` condition uses [`equals` or `notEquals`](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/definition-structure-policy-rule#conditions) with a literal value against a [field alias](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/definition-structure-alias) whose resource property is numeric (an integer or a number).

These operators coerce both operands to string and compare them case-insensitively. The comparison matches only when the literal is identical to the string form the property serializes to, so a literal whose string form differs will not match. For example, a property value of `5.0` stringifies to `"5.0"` and does not equal the literal `"5"`; a leading zero (`"05"`) has the same problem.

## Suggestions

- Test the policy and confirm the implicit string conversion produces the behavior you intend.
- For type-accurate equality, use `"value": "[equals(field('property'), 5)]", "equals": true`.

### Violation

```json
{
  "field": "Microsoft.Test/resourceType/floatProperty",
  "equals": "5"
}
```

### Correct

```json
{
  "field": "Microsoft.Test/resourceType/floatProperty",
  "equals": "5.0"
}
```
