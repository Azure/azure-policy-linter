# Parameter Missing Display Name

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| Misc | parameter-missing-display-name | Informational | — |

## Description

A policy parameter has no `metadata.displayName`. The definition is valid and accepted, but the Azure portal assignment experience shows the raw parameter name instead of a friendly label, which degrades the assignment UX. A whitespace-only or empty `displayName` is treated the same as a missing one.

See [parameter properties](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-parameters#parameter-properties) for the full set of parameter metadata.

## Suggestions

- Add a `metadata.displayName` to the parameter with a friendly, human-readable label.

## Examples

**Violation** -- parameter with no `displayName`; the portal shows the raw parameter name:

```json
"allowedLocations": {
  "type": "array"
}
```

**Correct** -- parameter with a `displayName`:

```json
"allowedLocations": {
  "type": "array",
  "metadata": { "displayName": "Allowed locations" }
}
```
