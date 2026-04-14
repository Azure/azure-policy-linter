# Verify claims() Function References Valid Claim Names

| Category | Identifier |
|----------------|------------------------|
| Misc | claims-function-usage |

## Description

Change Safety policies that use the `claims()` function must ensure that the referenced claim names are actually returned by the external evaluation endpoint. If a claim is not returned, policy evaluation will fail at runtime and may incorrectly deny legitimate requests.

The rule validates:
- All `claims()` function references must access a specific claim property (e.g., `claims().outcome`)
- The claim property path must be static (no dynamic claim names using parameters or expressions)
- The linter emits a warning for each claims() reference to remind you to verify the claim exists in your endpoint's response

### Examples

#### Valid: Accessing specific claim properties

```json
{
  "properties": {
    "policyRule": {
      "if": {
        "anyOf": [
          {
            "value": "[claims().outcome]",
            "notEquals": "Deferred"
          },
          {
            "value": "[claims().validationOutput.DataProcessed.value]",
            "greater": 0.0
          }
        ]
      },
      "then": {
        "effect": "deny"
      }
    }
  }
}
```

**Note:** The linter will emit warnings for each `claims()` reference reminding you to verify that `claims().outcome` and `claims().validationOutput.DataProcessed.value` are actually returned by your external evaluation endpoint.

#### Valid: Using claims() in field comparisons

```json
{
  "properties": {
    "policyRule": {
      "if": {
        "field": "location",
        "equals": "[claims().allowedRegion]"
      },
      "then": {
        "effect": "deny"
      }
    }
  }
}
```

**Note:** Claims() can be used in any context where template expressions are supported, not just in `value` conditions.

#### Invalid: Bare claims() without property access

```json
{
  "properties": {
    "policyRule": {
      "if": {
        "value": "[claims()]",
        "equals": "someValue"
      },
      "then": {
        "effect": "deny"
      }
    }
  }
}
```

**Error:** Bare `claims()` without property access is not allowed. Use `claims().propertyName` to access specific claims.

#### Invalid: Dynamic claim names using parameters

```json
{
  "properties": {
    "parameters": {
      "claimName": {
        "type": "String",
        "defaultValue": "outcome"
      }
    },
    "policyRule": {
      "if": {
        "value": "[claims()[parameters('claimName')]]",
        "equals": "Deferred"
      },
      "then": {
        "effect": "deny"
      }
    }
  }
}
```

**Error:** Dynamic claim names using parameters or expressions are not allowed. The claim path must be resolved at policy definition time.

### Suggestions

1. **Always verify claim names with your external evaluation endpoint**: Before deploying your policy, confirm that all claim names you reference (e.g., `outcome`, `validationOutput.DataProcessed.value`) are actually returned by your endpoint's response.

2. **Use specific property access**: Always use `claims().propertyName` to access specific claims. Bare `claims()` references are not allowed for Change Safety policies.

3. **Avoid dynamic claim names**: Do not use parameters or expressions to construct claim property names. The claim path must be resolved at policy definition time.

**Note:** Your endpoint may return different claims. Always verify with your endpoint's documentation or actual response data.

### Rule Set

This rule is part of the `ChangeSafety` rule set. To run this rule, use:

```
policylinter policy.json --rule-set ChangeSafety
```