# arg-validator-subscription-id-parameter

| Category | Identifier |
|------|-----------------------------------------|
| Misc | arg-validator-subscription-id-parameter |

## Description

When using ARG validator in ChangeSafety policies, the `subscriptionId` parameter should be set in `validationParameters`

This rule applies when:

1. The policy uses `externalEvaluationEnforcementSettings`
2. The `endpointSettings.kind` is `"ChangeSafetyValidation"`
3. The `validatorVersionId` contains `/validators/argValidator/` (case-insensitive)
4. For batch validators, the rule recursively checks all nested validators within `validationParameters`

The rule detects ARG validators at any nesting level, including:
- Top-level ARG validators (directly in `endpointSettings.details`)
- Nested ARG validators within batch validators (in `validationParameters` properties)

## Suggestions

### If you're using ARG validator

Add the `subscriptionId` parameter to `validationParameters`:

```json
{
  "externalEvaluationEnforcementSettings": {
    "endpointSettings": {
      "kind": "ChangeSafetyValidation",
      "details": {
        "validatorVersionId": "[concat('/subscriptions/', subscription().subscriptionId, '/providers/Microsoft.ChangeSafety/validators/argValidator/versions/0.0.1-beta')]",
        "validationParameters": {
          "subscriptionId": "[subscription().subscriptionId]",
          "argQuery": "resources | where type =~ 'microsoft.hdinsight/clusters' | project id, name"
        }
      }
    }
  }
}
```


When the rule detects a nested ARG validator missing `subscriptionId`, the warning message will include the path. Example:

```
When using ARG validator (in nested validator: softDeleteValidator), the subscriptionId parameter should be set in validationParameters...
```


## Related Rules

- `validator-path-subscription-id-hardcoded`: Checks that the `validatorVersionId` doesn't hardcode subscription GUIDs
- `endpoint-kind-must-be-change-safety-validation`: Validates the endpoint kind is correct

## Data sources

- [ARG Validator Documentation](https://dev.azure.com/msazure/One/_git/Azure-Validation-RP?path=/APISpec/ARGValidator.md&_a=preview&version=GBmain)
