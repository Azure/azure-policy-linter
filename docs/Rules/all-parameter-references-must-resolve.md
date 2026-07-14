# All Parameter References Must Resolve

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | all-parameter-references-must-resolve | Error | — |

## Description

Every `parameters('...')` reference in a policy definition must resolve to a parameter declared in the policy's `parameters` block. When the referenced parameter is not declared - including when the policy has no `parameters` block at all - the reference cannot resolve, so the policy fails to deploy or evaluate.

## Suggestions

- Verify the parameter name matches a declared parameter exactly (comparison is case-insensitive).
- Add the missing parameter to the `parameters` block, or correct the reference to point at an existing parameter.

See [Azure Policy definition structure - parameters](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-parameters) for how to declare parameters.

## Examples

### Violation

The parameter `efect` is referenced but only `effect` is defined:

```json
"parameters": {
  "effect": {
    "type": "String",
    "defaultValue": "Audit"
  }
},
"policyRule": {
  "if": {
    "field": "type",
    "equals": "Microsoft.Resources/subscriptions"
  },
  "then": {
    "effect": "[parameters('efect')]"
  }
}
```

### Correct

```json
"parameters": {
  "effect": {
    "type": "String",
    "defaultValue": "Audit"
  }
},
"policyRule": {
  "if": {
    "field": "type",
    "equals": "Microsoft.Resources/subscriptions"
  },
  "then": {
    "effect": "[parameters('effect')]"
  }
}
```
