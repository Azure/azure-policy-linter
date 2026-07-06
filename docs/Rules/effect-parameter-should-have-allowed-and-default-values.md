# Effect Parameter Should Have allowedValues and defaultValue

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | effect-parameter-should-have-allowed-and-default-values | Warning | — |

## Description

This rule checks that the effect parameter has both `allowedValues` and `defaultValue` defined. When either is missing, the policy lacks proper constraints on which effect values can be assigned, or does not specify a sensible default when the parameter is omitted at assignment time.

## Suggestions

- Add an `allowedValues` array to the effect parameter to restrict it to a known set of effect values (e.g. `["Audit", "Deny", "Disabled"]`).
- Add a `defaultValue` to the effect parameter so the policy behaves predictably when the parameter is not explicitly set during assignment.

## Examples

**Violation** -- effect parameter missing both `allowedValues` and `defaultValue`:

```json
"parameters": {
  "effect": {
    "type": "String"
  }
}
```

**Correct** -- effect parameter with both `allowedValues` and `defaultValue`:

```json
"parameters": {
  "effect": {
    "type": "String",
    "defaultValue": "Audit",
    "allowedValues": [
      "Audit",
      "Deny",
      "Disabled"
    ]
  }
}
```
