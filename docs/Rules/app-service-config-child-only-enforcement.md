# App Service Config Child-Only Enforcement

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | app-service-config-child-only-enforcement | Warning | default |

## Description

The policy is enforcing a rule on the `Microsoft.Web/sites/config` (or `Microsoft.Web/sites/slots/config`) resource type. App Service settings can also be set through the `siteConfig` property of the parent app in a `Microsoft.Web/sites` (or `Microsoft.Web/sites/slots`) request. This policy doesn't apply to changes made via the parent resource, and apps with non-compliant settings can still be created or updated.

## Suggestions

- Also enforce on `Microsoft.Web/sites` and check the matching `Microsoft.Web/sites/siteConfig.*` alias, with an `exists` condition on it (see [App Service Site Config Field Alias](app-service-site-config-field-alias.md)).
- You can do this in this policy, with an `anyOf` that has a branch for each resource type.
- Alternatively, create a separate policy targeting `Microsoft.Web/sites`.

## Examples

### Violation

```json
{
  "if": {
    "allOf": [
      { "field": "type", "equals": "Microsoft.Web/sites/config" },
      { "field": "Microsoft.Web/sites/config/ftpsState", "equals": "AllAllowed" }
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
          { "field": "type", "equals": "Microsoft.Web/sites/config" },
          { "field": "Microsoft.Web/sites/config/ftpsState", "equals": "AllAllowed" }
        ]
      },
      {
        "allOf": [
          { "field": "type", "equals": "Microsoft.Web/sites" },
          { "field": "Microsoft.Web/sites/siteConfig.ftpsState", "exists": true },
          { "field": "Microsoft.Web/sites/siteConfig.ftpsState", "equals": "AllAllowed" }
        ]
      }
    ]
  },
  "then": { "effect": "deny" }
}
```
