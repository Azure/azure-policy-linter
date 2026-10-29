# Ordering Operator on Incompatible Field Type in Old API Versions

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| ResourceFields | ordering-operator-on-incompatible-field-type-in-old-api-versions | Warning | default |

## Description

An ordering condition ([`greater`, `greaterOrEquals`, `less`, `lessOrEquals`](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#conditions)) compares a field alias whose data type in one or more older API versions can't be ordered against the comparison value. The comparison works in the latest API version, which compliance scans use. Requests that use an affected older API version fail evaluation, and a failed evaluation is an implicit deny.

The comparison rules are the same as in [Ordering Operator on Incompatible Field Type](ordering-operator-on-incompatible-field-type.md).

## Suggestions

- Convert the field with a template function in a `value` condition, so the comparison works with every API version. `float()` converts both numbers and numeric strings. See [Ordering Operator on Incompatible Field Type](ordering-operator-on-incompatible-field-type.md#suggestions) for the options and their limitations.

## Examples

### Violation

`Microsoft.Sql/servers/databases/maxSizeBytes` is an integer in the latest API versions and a string in API version `2014-04-01`.

```json
{
  "field": "Microsoft.Sql/servers/databases/maxSizeBytes",
  "greater": 268435456000
}
```

### Correct

```json
{
  "value": "[if(equals(field('Microsoft.Sql/servers/databases/maxSizeBytes'), ''), float(0), float(field('Microsoft.Sql/servers/databases/maxSizeBytes')))]",
  "greater": 268435456000.0
}
```
