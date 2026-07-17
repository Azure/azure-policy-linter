# Parameter Missing Display Name

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | parameter-missing-display-name | Informational | default |

## Description

A policy parameter does not define a non-empty `metadata.displayName`. The definition is still valid, but whoever assigns the policy sees the raw parameter name instead of a friendly label, which degrades the assignment experience.

See [parameter properties](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-parameters#parameter-properties) for the `metadata.displayName` property.

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
