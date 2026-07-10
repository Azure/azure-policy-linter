# Effect Parameter Missing Allowed Values

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | effect-parameter-missing-allowed-values | Warning | — |

## Description

The policy effect is parameterized, but the parameter does not constrain its `allowedValues`. An absent or empty `allowedValues` lets the parameter accept any value at assignment time, including effects the policy was never designed to apply. Constraining the effect to a known set keeps assignments predictable and prevents invalid or unintended effects.

See the [parameterized effect sample](https://learn.microsoft.com/azure/governance/policy/samples/pattern-parameters#sample-3-parameterized-effect) for the canonical pattern.

## Suggestions

- Add an `allowedValues` array to the effect parameter listing the effects the policy supports (e.g. `["Audit", "Deny", "Disabled"]`).

## Examples

**Violation** -- effect parameter with no `allowedValues`:

```json
"parameters": {
  "effect": {
    "type": "string"
  }
}
```

**Correct** -- effect parameter constrained to a known set:

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
