# App Service Config Field Alias

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| ResourceFields | app-service-config-field-alias | Warning | default |

## Description

The policy checks App Service settings through `Microsoft.Web/sites/siteConfig.*` or `Microsoft.Web/sites/config/*` field aliases (or their `Microsoft.Web/sites/slots` equivalents). These settings can be changed through two resources, and some of them are returned as null when reading an existing app. This can result in policies not behaving as expected.

### Settings Changed Through Two Resources

App Service settings can be set through the `siteConfig` property of the app in a `Microsoft.Web/sites` request, or through the app's `Microsoft.Web/sites/config` child resource. A policy that enforces on only one of these resource types doesn't apply to changes made through the other, and apps can still be changed to non-compliant settings. This applies to `config` field aliases that have a matching `siteConfig` alias; other config settings, such as authentication and logging, can't be set through `siteConfig`.

### Null Setting Values Returned by the Resource Provider

Some properties under `siteConfig` are known to be returned as null when reading an existing app, even when they are set.

When scanned for compliance, these properties have a `null` value, resulting in incorrect [compliance results](https://learn.microsoft.com/azure/governance/policy/concepts/compliance-states).

In enforcement scenarios, `PUT` requests can be used to update a subset of the `siteConfig` properties while leaving all other properties unchanged (i.e. the `PUT` request acts more like a `PATCH`).
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

## Suggestions

- Enforce on both `Microsoft.Web/sites` (with the `siteConfig.*` alias) and `Microsoft.Web/sites/config` (with the matching `config/*` alias). You can do this in one policy, with an `anyOf` that has a branch for each resource type, or in separate policies.
- On the `siteConfig.*` alias, add an [`exists`](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#conditions) condition with the value `true`, so the condition doesn't match when the property is returned as null. This prevents incorrect enforcement, but doesn't fix compliance results.
- To report compliance on the setting, rely on the `Microsoft.Web/sites/config/*` field alias on the child `Microsoft.Web/sites/config` resource type.

## Examples

### Violation

The policy enforces only through the `siteConfig.*` alias, without an `exists` condition.

```json
{
  "if": {
    "allOf": [
      { "field": "type", "equals": "Microsoft.Web/sites" },
      { "field": "Microsoft.Web/sites/siteConfig.ftpsState", "notEquals": "Disabled" }
    ]
  },
  "then": { "effect": "deny" }
}
```

### Correct

The rule still reports this policy, because it references these field aliases.

```json
{
  "if": {
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
  },
  "then": { "effect": "deny" }
}
```
