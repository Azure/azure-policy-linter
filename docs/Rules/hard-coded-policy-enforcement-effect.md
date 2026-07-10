# Hard-Coded Policy Enforcement Effect

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | hard-coded-policy-enforcement-effect | Warning | — |

## Description

The policy definition hard-codes an enforcement effect (`deployIfNotExists`, `append`, `modify`, `deny`, or `denyAction`) instead of parameterizing it. It is best practice to parameterize the policy effect, especially for enforcement policies. Having the policy effect determined by a parameter has the following advantages:

- The policy definition can be reused both for enforcement (e.g. when the effect parameter is set to `deny`) and for compliance (the effect parameter set to `audit`) scenarios.
- It makes it easier to assign the policy with an audit effect first, observe the compliance data and then gradually transition it to the enforcement effect.

Hard-coded non-enforcement effects (`audit`, `auditIfNotExists`, `disabled`) are deliberately not flagged.

See [Azure Policy definitions effect basics](https://learn.microsoft.com/azure/governance/policy/concepts/effect-basics) for the list of effects.

## Suggestions

- Use a parameterized effect for the policy. The effect parameter should have a non-enforcement default value (or no default value at all) and specific allowed values. For example, for a `deny` policy, the effect parameter should default to `audit` with allowed values `audit`, `deny` and `disabled`.

## Examples

**Violation** -- hard-coded enforcement effect:

```json
"then": {
  "effect": "deny"
}
```

**Correct** -- parameterized effect:

```json
"parameters": {
  "effect": {
    "type": "string",
    "defaultValue": "audit",
    "allowedValues": [
      "audit",
      "deny",
      "disabled"
    ]
  }
},
"policyRule": {
  "then": {
    "effect": "[parameters('effect')]"
  }
}
```
