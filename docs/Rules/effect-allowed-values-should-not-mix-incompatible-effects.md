# Effect Allowed Values Should Not Mix Incompatible Effects

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | effect-allowed-values-should-not-mix-incompatible-effects | Error | — |

## Description

When the [`effect`](https://learn.microsoft.com/azure/governance/policy/concepts/effect-basics) is a parameter reference, every allowed effect shares the single static `then.details` block. Some effects require their own `details` shape, so allowing effects with different `details` shapes leaves at least one allowed value without a valid `details` block. Each of the following sets of effects requires its own `details` shape, and effects from different sets cannot coexist in the same `allowedValues`:

- [`Modify`](https://learn.microsoft.com/azure/governance/policy/concepts/effect-modify)
- [`AuditIfNotExists`](https://learn.microsoft.com/azure/governance/policy/concepts/effect-audit-if-not-exists), [`DeployIfNotExists`](https://learn.microsoft.com/azure/governance/policy/concepts/effect-deploy-if-not-exists)
- [`DenyAction`](https://learn.microsoft.com/azure/governance/policy/concepts/effect-deny-action)
- [`Append`](https://learn.microsoft.com/azure/governance/policy/concepts/effect-append)
- [`Manual`](https://learn.microsoft.com/azure/governance/policy/concepts/effect-manual)

Effects that need no `details` block ([`Audit`](https://learn.microsoft.com/azure/governance/policy/concepts/effect-audit), [`Deny`](https://learn.microsoft.com/azure/governance/policy/concepts/effect-deny), [`Disabled`](https://learn.microsoft.com/azure/governance/policy/concepts/effect-disabled)) are compatible with any of the above.

This rule is skipped for dataplane policy modes (e.g. `Microsoft.Kubernetes.Data`) since they may use effects not in the known set.

## Suggestions

Restrict `allowedValues` to effects from a single compatible set plus any effect that needs no `details` block (`Audit`, `Deny`, `Disabled`).

## Examples

### Violation

```json
"allowedValues": ["Modify", "DeployIfNotExists", "Disabled"]
```

`Modify` and `DeployIfNotExists` require different `details` shapes.

### Correct

```json
"allowedValues": ["Audit", "Modify", "Disabled"]
```

```json
"allowedValues": ["Audit", "Deny", "Disabled"]
```

```json
"allowedValues": ["AuditIfNotExists", "DeployIfNotExists", "Disabled"]
```
