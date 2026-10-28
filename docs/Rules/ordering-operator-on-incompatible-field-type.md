# Ordering Operator on Incompatible Field Type

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| ResourceFields | ordering-operator-on-incompatible-field-type | Error | default |

## Description

An ordering condition ([`greater`, `greaterOrEquals`, `less`, `lessOrEquals`](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/definition-structure-policy-rule#conditions)) compares a field alias whose data type in the latest API version cannot be ordered against the comparison value's type. Azure Policy throws when the field's type doesn't match the comparison value's type: a numeric field orders only against a number, an integer field orders only against a whole number (not a decimal value such as `2.5` or `2.0`), a string field orders only against a string or a date, and boolean, object, and array fields cannot be ordered at all. A failed evaluation is an implicit deny, so a definition that passes authoring validation silently denies or errors on resources whenever the comparison is reached.

The rule fires when the field's type in the latest known API version is incompatible, including when the type is incompatible in every known API version. Incompatibilities limited to older API versions are reported by [Ordering Operator on Incompatible Field Type in Old API Versions](ordering-operator-on-incompatible-field-type-in-old-api-versions.md).

## Suggestions

- If the comparison value has the wrong type, change it to match the field. For example, compare an integer field against a whole number.
- Otherwise, convert the field with a template function in a [`value` condition](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#value), so both sides have the same type:
  - Convert to a decimal number with `float()`, and write the comparison value as a decimal number (`2.0`, not `2`). Evaluation fails when the property is missing or isn't a number.

    ```json
    { "value": "[float(field('Microsoft.Test/resourceType/size'))]", "greater": 2.0 }
    ```

  - Convert to a decimal number with `float()` and check for a missing property first. A missing property is returned as an empty string; set the fallback value to the value that gives the result you want for a missing property.

    ```json
    {
      "value": "[if(equals(field('Microsoft.Test/resourceType/size'), ''), float(0), float(field('Microsoft.Test/resourceType/size')))]",
      "greater": 2.0
    }
    ```

  - Convert to a string with `string()`, and compare against a string. This works for string and integer fields, but strings are compared as text: it gives correct results only when text order matches the order you want, such as ISO 8601 dates or values with the same number of digits (`"9"` is greater than `"10"`).

    ```json
    { "value": "[string(field('Microsoft.Test/resourceType/tier'))]", "greaterOrEquals": "3" }
    ```

- Boolean, object, and array fields can't be ordered. Compare the specific property you care about with `equals`, `exists`, or a `count` condition.

## Examples

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
