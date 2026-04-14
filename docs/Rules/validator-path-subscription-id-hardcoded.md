# Validator Path Must Not Hardcode subscriptionId

| Category | Identifier |
|----------------|------------------------------------------|
| Misc | validator-path-subscription-id-hardcoded |

## Description

Change Safety policies must not hardcode subscription IDs in the `validatorVersionId` path. The `validatorVersionId` must use the `subscription().subscriptionId` template function to dynamically reference the subscription ID at runtime.

The rule validates:
- The `validatorVersionId` must be a template expression
- The template expression must contain `subscription().subscriptionId` to dynamically retrieve the subscription GUID
- Hardcoded subscription IDs or non-template expressions are not allowed

### Suggestion

Always use this pattern for `validatorVersionId`:

```
[concat('/subscriptions/', subscription().subscriptionId, '/providers/Microsoft.ChangeSafety/validators/<validatorName>/versions/<version>')]
```

Replace `<validatorName>` and `<version>` with your specific validator details. 

#### Valid: Uses `subscription().subscriptionId`

```json
{
  "properties": {
    "externalEvaluationEnforcementSettings": {
      "roleDefinitionIds": [],
      "endpointSettings": {
        "kind": "ChangeSafetyValidation",
        "details": {
          "validatorVersionId": "[concat('/subscriptions/', subscription().subscriptionId, '/providers/Microsoft.ChangeSafety/validators/metricsValidator/versions/0.0.1-beta')]"
        }
      }
    }
  }
}
```

### Rule Set

This rule is part of the `ChangeSafety` rule set. To run this rule, use:

```
policylinter policy.json --rule-set ChangeSafety
```