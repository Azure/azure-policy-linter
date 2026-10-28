# App Service Config Parent-Only Enforcement

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | app-service-config-parent-only-enforcement | Warning | default |

## Description

The policy is enforcing a rule on App Service settings through `Microsoft.Web/sites/siteConfig.*` (or `Microsoft.Web/sites/slots/siteConfig.*`) field aliases. The same settings can also be changed through the app's `Microsoft.Web/sites/config` (or `Microsoft.Web/sites/slots/config`) resource. Azure Policy evaluates those requests only against the `config` resource type, so this policy doesn't apply to them, and apps can still be changed to non-compliant settings.

## Suggestions

- Also enforce on `Microsoft.Web/sites/config` and check the matching `Microsoft.Web/sites/config/*` alias.
- You can do this in this policy, with an `anyOf` that has a branch for each resource type.
- Alternatively, create a separate policy targeting `Microsoft.Web/sites/config`.

## Examples

### Violation

```json
{
  "if": {
    "allOf": [
      { "field": "type", "equals": "Microsoft.Web/sites" },
      { "field": "Microsoft.Web/sites/siteConfig.ftpsState", "exists": true },
      { "field": "Microsoft.Web/sites/siteConfig.ftpsState", "equals": "AllAllowed" }
    ]
  },
  "then": { "effect": "deny" }
}
```

### Correct

```json
{
  "if": {
    "anyOf": [
      {
        "allOf": [
          { "field": "type", "equals": "Microsoft.Web/sites" },
          { "field": "Microsoft.Web/sites/siteConfig.ftpsState", "exists": true },
          { "field": "Microsoft.Web/sites/siteConfig.ftpsState", "equals": "AllAllowed" }
        ]
      },
      {
        "allOf": [
          { "field": "type", "equals": "Microsoft.Web/sites/config" },
          { "field": "Microsoft.Web/sites/config/ftpsState", "equals": "AllAllowed" }
        ]
      }
    ]
  },
  "then": { "effect": "deny" }
}
```
