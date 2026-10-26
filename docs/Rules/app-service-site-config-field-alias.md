# App Service Site Config Field Alias

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| ResourceFields | app-service-site-config-field-alias | Warning | default |

## Description

The policy reads a `Microsoft.Web/sites/siteConfig.*` (or `Microsoft.Web/sites/slots/siteConfig.*`) field alias. The App Service resource provider returns these properties empty when Azure Policy reads existing apps, so the [compliance results](https://learn.microsoft.com/azure/governance/policy/concepts/compliance-states) of this policy don't reflect the actual app settings.

The `siteConfig.*` aliases are still the right choice for `deny`, `append`, and `modify` policies, because the values are present in the request that creates or updates the app.

## Suggestions

- To report compliance on App Service settings, use an `auditIfNotExists` or `deployIfNotExists` policy that targets `Microsoft.Web/sites` and checks the `Microsoft.Web/sites/config` resource named `web` in its `existenceCondition`.
- To block non-compliant settings, use a `deny` policy with the `siteConfig.*` alias, and pair it with an `auditIfNotExists` policy for compliance.

See the Azure Policy team's comment in [Azure/azure-policy#398](https://github.com/Azure/azure-policy/issues/398#issuecomment-497161551).

## Examples

### Violation

```json
{
  "if": {
    "allOf": [
      { "field": "type", "equals": "Microsoft.Web/sites" },
      { "field": "Microsoft.Web/sites/siteConfig.ftpsState", "equals": "AllAllowed" }
    ]
  },
  "then": { "effect": "audit" }
}
```

### Correct

```json
{
  "if": { "field": "type", "equals": "Microsoft.Web/sites" },
  "then": {
    "effect": "auditIfNotExists",
    "details": {
      "type": "Microsoft.Web/sites/config",
      "name": "web",
      "existenceCondition": {
        "field": "Microsoft.Web/sites/config/ftpsState",
        "notEquals": "AllAllowed"
      }
    }
  }
}
```
