# Nested Same-Type Quantifiers Should Be Flattened

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | nested-same-type-quantifiers-should-be-flattened | Informational | default |

## Description

An `allOf` or `anyOf` contains a child that is itself an `allOf` or `anyOf` of the same type. Since both operators are associative, the inner quantifier's children can be merged directly into the outer one, reducing unnecessary nesting.

See [logical operators](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule) in the Azure Policy definition structure.

## Suggestions

Move the children of the inner quantifier into the outer quantifier and remove the redundant nesting.

### Violation

```json
"if": {
  "allOf": [
    {
      "field": "type",
      "equals": "Microsoft.Compute/virtualMachines"
    },
    {
      "allOf": [
        {
          "field": "location",
          "equals": "eastus"
        },
        {
          "field": "tags.env",
          "equals": "prod"
        }
      ]
    }
  ]
}
```

### Correct

```json
"if": {
  "allOf": [
    {
      "field": "type",
      "equals": "Microsoft.Compute/virtualMachines"
    },
    {
      "field": "location",
      "equals": "eastus"
    },
    {
      "field": "tags.env",
      "equals": "prod"
    }
  ]
}
```
