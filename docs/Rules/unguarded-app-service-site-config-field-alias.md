# Unguarded App Service Site Config Field Alias

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| ResourceFields | unguarded-app-service-site-config-field-alias | Warning | default |

## Description

The policy checks a `Microsoft.Web/sites/siteConfig.*` (or `Microsoft.Web/sites/slots/siteConfig.*`) field alias without an `exists` condition on it. Some properties under `siteConfig` are known to be returned as null when Azure Policy reads an existing app, even when they are set. For those properties, the policy evaluates the field as empty, so its [compliance results](https://learn.microsoft.com/azure/governance/policy/concepts/compliance-states) don't reflect the real value.

The same settings are returned with their real values by the app's `Microsoft.Web/sites/config` resource named `web`.

## Suggestions

- Add an [`exists`](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#conditions) condition with the value `true` on the same field alias, so the condition doesn't match when the property is returned as null.
- To report compliance on the setting, also check the matching `Microsoft.Web/sites/config/*` field alias on the `Microsoft.Web/sites/config` resource type, in this policy or in a separate one.

## Examples

### Violation

```json
{
  "allOf": [
    { "field": "type", "equals": "Microsoft.Web/sites" },
    { "field": "Microsoft.Web/sites/siteConfig.ftpsState", "notEquals": "Disabled" }
  ]
}
```

### Correct

```json
{
  "anyOf": [
    {
      "allOf": [
        { "field": "type", "equals": "Microsoft.Web/sites" },
        { "field": "Microsoft.Web/sites/siteConfig.ftpsState", "exists": true },
        { "field": "Microsoft.Web/sites/siteConfig.ftpsState", "notEquals": "Disabled" }
      ]
    },
    {
      "allOf": [
        { "field": "type", "equals": "Microsoft.Web/sites/config" },
        { "field": "Microsoft.Web/sites/config/ftpsState", "notEquals": "Disabled" }
      ]
    }
  ]
}
```
