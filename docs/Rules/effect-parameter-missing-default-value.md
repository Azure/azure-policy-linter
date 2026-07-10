# Effect Parameter Missing Default Value

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | effect-parameter-missing-default-value | Warning | — |

## Description

The policy effect is parameterized, but the parameter does not define a `defaultValue`. Without a default, the effect must be supplied at every assignment and the policy has no predictable behavior when it is omitted. A default value lets the policy be assigned as-is and documents the effect the author intended.

See the [parameterized effect sample](https://learn.microsoft.com/azure/governance/policy/samples/pattern-parameters#sample-3-parameterized-effect) for the canonical pattern.

## Suggestions

- Add a `defaultValue` to the effect parameter so the policy behaves predictably when the parameter is not set during assignment.

## Examples

**Violation** -- effect parameter with no `defaultValue`:

```json
"parameters": {
  "effect": {
    "type": "string",
    "allowedValues": [
      "Audit",
      "Deny",
      "Disabled"
    ]
  }
}
```

**Correct** -- effect parameter with a `defaultValue`:

```json
"parameters": {
  "effect": {
    "type": "string",
    "defaultValue": "Audit",
    "allowedValues": [
      "Audit",
      "Deny",
      "Disabled"
    ]
  }
}
```
