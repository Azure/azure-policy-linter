# Effect Allowed Values Should Not Mix Incompatible Effects

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | effect-allowed-values-should-not-mix-incompatible-effects | Error | — |

## Description

The effect parameter's `allowedValues` mixes effects that require incompatible `details` block configurations. Each of the following sets of effects requires its own `details` shape, so effects from different sets cannot coexist in the same `allowedValues`:

- `Modify`
- `AuditIfNotExists`, `DeployIfNotExists`
- `DenyAction`, `AuditAction`
- `Append`

Effects that do not require a specific `details` block (`Audit`, `Deny`, `Disabled`, `Manual`) are compatible with any of the above.

This rule is skipped for dataplane policy modes (e.g. `Microsoft.Kubernetes.Data`) since they may use effects not in the known set.

## Suggestions

Restrict `allowedValues` to effects from a single compatible set plus any universally compatible effects. For example:

**Violation**

```json
"allowedValues": ["Modify", "DeployIfNotExists", "Disabled"]
```

`Modify` and `DeployIfNotExists` require different `details` configurations.

**Correct**

```json
"allowedValues": ["Audit", "Modify", "Disabled"]
```

```json
"allowedValues": ["Audit", "Deny", "Disabled"]
```

```json
"allowedValues": ["AuditIfNotExists", "DeployIfNotExists", "Disabled"]
```
