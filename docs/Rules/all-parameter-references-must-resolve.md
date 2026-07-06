# All Parameter References Must Resolve

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | all-parameter-references-must-resolve | Error | — |

## Description

Every `parameters('...')` reference in a policy definition must correspond to a parameter that is actually defined in the policy's `parameters` block.

## Suggestions

- Verify the parameter name matches a defined parameter exactly (comparison is case-insensitive).
- Check for common typos (e.g. `parameters('efect')` instead of `parameters('effect')`).
- If the parameter was intentionally removed, update all references that still point to it.

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
