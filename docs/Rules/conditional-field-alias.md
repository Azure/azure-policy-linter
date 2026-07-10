# Conditional Field Alias

| Category | Identifier | Severity | Rule Set |
|----------------|-------------------------|----------|----------|
| ResourceFields | conditional-field-alias | Warning  | —        |

## Description

The policy definition is referencing a [field alias](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/definition-structure-alias) that maps to a property that is annotated as conditional by the resource provider in one or more API versions. This means the property only exists when a specific condition is met. This is typical for resources that implement a typing system: for example, Azure Data Factory triggers have different trigger "kinds", and each trigger kind has its own properties.

If the policy rule ignores these conditions and expects the property to always exist, it may produce incorrect evaluation results.

This rule is distinct from `optional-field-alias`. A conditional property does not exist at all unless its condition is met (for example, the wrong trigger kind), whereas an optional property always belongs to the resource type but is simply not required in a request. A single field can trigger both rules.

### Suggestions

- Consult the resource provider documentation to find the exact condition under which the property exists (this may require trial and error).
- Guard the reference with that condition so the property is only evaluated when it exists. See the correct example below.
- If you cannot express the exact condition, decide what the desired policy outcome is when the property is missing:
  - If deciding not to enforce, add an `exists` condition to the policy rule.
  - If deciding to enforce, assign the policy with an `audit` effect first and inspect the [activity logs](https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log-schema#policy-category) for audit events to gauge how often the condition is unmet before switching to enforcement.

## Examples

### Triggers the rule

The `ScheduleTrigger.typeProperties.recurrence.frequency` alias only exists for schedule triggers, so referencing it without guarding the trigger kind warns that the property may be missing for other trigger kinds.

```json
{
  "if": {
    "field": "Microsoft.DataFactory/factories/triggers/ScheduleTrigger.typeProperties.recurrence.frequency",
    "equals": "Day"
  },
  "then": { "effect": "audit" }
}
```

### Correct

Guard the reference with the trigger kind so the policy only evaluates the property when it exists:

```json
{
  "if": {
    "allOf": [
      { "field": "Microsoft.DataFactory/factories/triggers/type", "equals": "ScheduleTrigger" },
      { "field": "Microsoft.DataFactory/factories/triggers/ScheduleTrigger.typeProperties.recurrence.frequency", "equals": "Day" }
    ]
  },
  "then": { "effect": "audit" }
}
```

The linter inspects alias references, not the surrounding conditions, so it still reports the conditional alias here. The guard does not silence the rule; it ensures the policy evaluates correctly at runtime.

## Data sources

- Resource metadata is derived from the public [Azure REST API specs](https://github.com/Azure/azure-rest-api-specs/tree/main/specification).
- The linter repo contains a dump of all available policy aliases **from the public cloud**.
