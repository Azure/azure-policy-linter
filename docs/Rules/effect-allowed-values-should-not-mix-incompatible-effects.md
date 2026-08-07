# Effect Allowed Values Should Not Mix Incompatible Effects

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | effect-allowed-values-should-not-mix-incompatible-effects | Error | default |

## Description

Parameterized [`effect`](https://learn.microsoft.com/azure/governance/policy/concepts/effect-basics#interchanging-effects) values share one policy rule and `then.details` configuration. Azure Policy documents [`Audit`](https://learn.microsoft.com/azure/governance/policy/concepts/effect-audit), [`Deny`](https://learn.microsoft.com/azure/governance/policy/concepts/effect-deny), and either [`Modify`](https://learn.microsoft.com/azure/governance/policy/concepts/effect-modify) or [`Append`](https://learn.microsoft.com/azure/governance/policy/concepts/effect-append) as often interchangeable, and [`AuditIfNotExists`](https://learn.microsoft.com/azure/governance/policy/concepts/effect-audit-if-not-exists) and [`DeployIfNotExists`](https://learn.microsoft.com/azure/governance/policy/concepts/effect-deploy-if-not-exists) as often interchangeable. [`Manual`](https://learn.microsoft.com/azure/governance/policy/concepts/effect-manual) is not interchangeable, while [`Disabled`](https://learn.microsoft.com/azure/governance/policy/concepts/effect-disabled) is interchangeable with any effect; [`DenyAction`](https://learn.microsoft.com/azure/governance/policy/concepts/effect-deny-action) also uses its own `details` configuration. This rule is skipped for dataplane policy modes such as `Microsoft.Kubernetes.Data`.

## Suggestions

Restrict `allowedValues` to interchangeable effects. Keep `Manual` separate from every effect except `Disabled`.

## Examples

### Violation

```json
"allowedValues": ["Audit", "Manual", "Disabled"]
```

`Audit` and `Manual` are not interchangeable.

### Correct

```json
"allowedValues": ["Manual", "Disabled"]
```
