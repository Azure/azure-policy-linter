# Parameter Missing Description

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | parameter-missing-description | Informational | — |

## Description

A policy or initiative parameter does not define a non-empty `metadata.description`. The definition is still valid, but whoever assigns the policy gets no guidance on what the parameter is for or what values are acceptable, which degrades the assignment experience.

See [parameter properties](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-parameters#parameter-properties) for the `metadata.description` property.

## Suggestions

- Add a `metadata.description` to the parameter explaining what it is used for. It can also give examples of acceptable values.

## Examples

**Violation** -- parameter with no `metadata.description`:

```json
"allowedLocations": {
  "type": "array"
}
```

**Correct** -- parameter with a `metadata.description`:

```json
"allowedLocations": {
  "type": "array",
  "metadata": { "description": "The list of locations that resources can be deployed into." }
}
```
