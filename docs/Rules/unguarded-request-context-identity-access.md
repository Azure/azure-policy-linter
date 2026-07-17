# Unguarded Request Context Identity Access

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | unguarded-request-context-identity-access | Warning | default |

## Description

`requestContext().identity` is always present during evaluation, but its sub-properties - individual identity claims in particular - are not guaranteed to appear in every auth token. Claims are keys directly on the identity object (for example `requestContext().identity['http://schemas.microsoft.com/identity/claims/objectidentifier']`). Selecting one of those keys directly fails at evaluation time when it is absent, and [a failed template evaluation is an implicit deny](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#avoiding-template-failures). This rule flags a property selection that goes one or more segments past `requestContext().identity` without a safe-access guard.

## Suggestions

- Wrap the access in [`tryGet`](https://learn.microsoft.com/azure/governance/policy/how-to/using-request-context-identity#pattern-safely-read-identity-fields-with-tryget), passing the claim key as its second argument: `tryGet(requestContext().identity, '<claim>')`. `tryGet` returns `null` when its first key is missing instead of failing. It safe-dereferences only that first key, so pass the full claim key as a single argument rather than chaining further segments.
- Combine with `coalesce` to supply a fallback value when the claim is absent.
- Selecting `requestContext().identity` itself is safe and does not need a guard.

## Examples

### Violation

An absent claim makes the expression fail, denying the request:

```json
{
  "value": "[requestContext().identity['http://schemas.microsoft.com/identity/claims/objectidentifier']]",
  "notIn": "[parameters('approvedObjectIds')]"
}
```

### Correct

`tryGet` returns `null` for an absent claim, and `coalesce` supplies a fallback:

```json
{
  "value": "[coalesce(tryGet(requestContext().identity, 'http://schemas.microsoft.com/identity/claims/objectidentifier'), '')]",
  "notIn": "[parameters('approvedObjectIds')]"
}
```
