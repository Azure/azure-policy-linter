# Ordering Operator on Incompatible Field Type in Old API Versions

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| ResourceFields | ordering-operator-on-incompatible-field-type-in-old-api-versions | Warning | default |

## Description

An ordering condition ([`greater`, `greaterOrEquals`, `less`, `lessOrEquals`](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#conditions)) compares a field alias whose data type in one or more older API versions can't be ordered against the comparison value. The comparison works in the latest API version, which compliance scans use. Requests that use an affected older API version fail evaluation, and a failed evaluation is an implicit deny.

The comparison rules are the same as in [Ordering Operator on Incompatible Field Type](ordering-operator-on-incompatible-field-type.md).

## Suggestions

- Check whether clients in your environment still send requests with the API versions in the finding.
- To handle older API versions explicitly, add a condition on `[requestContext().apiVersion]` that skips or handles the comparison for those versions.
- To find affected requests before enforcing, assign the policy with the `audit` effect and inspect the [activity logs](https://learn.microsoft.com/azure/azure-monitor/essentials/activity-log-schema#policy-category).

## Examples

### Violation

The field is a number in the latest API version and a string in an older API version.

```json
{
  "field": "Microsoft.Test/resourceType/size",
  "greater": 100
}
```

### Correct

```json
{
  "allOf": [
    { "value": "[requestContext().apiVersion]", "greaterOrEquals": "2023-01-01" },
    { "field": "Microsoft.Test/resourceType/size", "greater": 100 }
  ]
}
```
