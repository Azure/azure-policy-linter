# App Service Site Config Field Alias

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| ResourceFields | app-service-site-config-field-alias | Warning | default |

## Description

The policy checks a `Microsoft.Web/sites/siteConfig.*` (or `Microsoft.Web/sites/slots/siteConfig.*`) field alias. Some properties under `siteConfig` are known to be returned as null when reading an existing app, even when they are set. This can result in policies not behaving as expected.

### Incorrect Enforcement

`PUT` requests can be used to update a subset of the `siteConfig` properties while leaving all other properties unchanged (i.e. the `PUT` request acts more like a `PATCH`).
An enforcement policy expecting a `siteConfig` property to have an explicit value can treat these missing or null properties as having a non-compliant value.

**Example:**

**Existing resource has FTP disabled:**

```json
{
  "type": "Microsoft.Web/sites",
  "properties": {
    "siteConfig": {
      "ftpsState": "Disabled",
      "otherProperty": "a"
    }
  }
}
```

**A PUT request can be used to "patch" `otherProperty`:**

```json
{
  "type": "Microsoft.Web/sites",
  "properties": {
    "siteConfig": {
      "ftpsState": null,
      "otherProperty": "b"
    }
  }
}
```

A policy might interpret the missing or null value of `ftpsState` as an attempt to set it to a non-compliant value.

**After update, FTP is still disabled:**

```json
{
  "type": "Microsoft.Web/sites",
  "properties": {
    "siteConfig": {
      "ftpsState": "Disabled",
      "otherProperty": "b"
    }
  }
}
```

### Incorrect Compliance

When scanned for compliance, these properties have a `null` value, resulting in incorrect [compliance results](https://learn.microsoft.com/azure/governance/policy/concepts/compliance-states).

## Suggestions

- Add an [`exists`](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#conditions) condition with the value `true` on the same field alias, so the condition doesn't match when the property is returned as null. This prevents incorrect enforcement, but doesn't fix compliance results.
- To report compliance on the setting, also check the matching `Microsoft.Web/sites/config/*` field alias on the child `Microsoft.Web/sites/config` resource type, in this policy or in a separate one.

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
