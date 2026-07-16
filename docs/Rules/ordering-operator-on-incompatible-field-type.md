# Ordering Operator on Incompatible Field Type

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| ResourceFields | ordering-operator-on-incompatible-field-type | Error | — |

## Description

An ordering condition ([`greater`, `greaterOrEquals`, `less`, `lessOrEquals`](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/definition-structure-policy-rule#conditions)) compares a field alias whose known data type cannot be ordered against the comparison value's type. Azure Policy throws when the field's type doesn't match the comparison value's type: a numeric field orders only against a number, a string field orders only against a string or a date, and boolean, object, and array fields cannot be ordered at all. A [failed evaluation is an implicit deny](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/definition-structure-policy-rule#avoiding-template-failures), so a definition that passes authoring validation silently denies or errors on resources whenever the comparison is reached.

## Suggestions

- Order a numeric field against a number. To compare a date, use a string field (dates are stored as strings) and an ISO 8601 date value.
- Don't compare a string field against a number, or use an ordering operator on a boolean, object, or array field. Compare the specific property you care about with `equals`, `exists`, or a `count` condition instead.

### Violation

```json
{
  "field": "Microsoft.Web/sites/httpsOnly",
  "greater": 5
}
```

### Correct

```json
{
  "field": "Microsoft.Compute/virtualMachines/storageProfile.osDisk.diskSizeGB",
  "greater": 128
}
```
