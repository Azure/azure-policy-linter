# Ordering Operator on Incompatible Field Type

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| ResourceFields | ordering-operator-on-incompatible-field-type | Error | — |

## Description

An ordering condition ([`greater`, `greaterOrEquals`, `less`, `lessOrEquals`](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/definition-structure-policy-rule#conditions)) compares a field alias whose known data type cannot be ordered against the comparison value's type. Boolean, object, and array fields cannot be ordered at all, and a numeric field can only be ordered against a number or a date. When the operand types don't match, the platform throws at evaluation. A [failed evaluation is an implicit deny](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/definition-structure-policy-rule#avoiding-template-failures), so a definition that passes authoring validation silently denies or errors on resources whenever the comparison is reached.

## Suggestions

- Order a numeric field against a number, or against an ISO 8601 date when comparing dates.
- Don't use an ordering operator on a boolean, object, or array field. Compare the specific property you care about with `equals`, `exists`, or a `count` condition instead.

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
