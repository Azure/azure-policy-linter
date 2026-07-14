# Unguarded Request Context Identity Access

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | unguarded-request-context-identity-access | Warning | — |

## Description

`requestContext().identity` is always present during evaluation, but its sub-properties - individual `claims` in particular - are not guaranteed to appear in every auth token. Selecting one of those sub-properties directly (for example `requestContext().identity.claims['...']`) fails at evaluation time when the path is absent, and [a failed template evaluation is an implicit deny](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#avoiding-template-failures). This rule flags a property selection that goes one or more segments past `requestContext().identity` without a safe-access guard.

## Suggestions

- Wrap the access in [`tryGet`](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule), which returns `null` when any path segment is missing instead of failing. Pass each segment as a separate argument: `tryGet(requestContext().identity, 'claims', '<claim>')`.
- Combine with `coalesce` to supply a fallback value when the segment is absent.
- Selecting `requestContext().identity` itself is safe and does not need a guard.

## Examples

### Violation

An absent claim makes the expression fail, denying the request:

```json
{
  "value": "[requestContext().identity.claims['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/role']]",
  "equals": "admin"
}
```

### Correct

`tryGet` returns `null` for an absent claim, and `coalesce` supplies a fallback:

```json
{
  "value": "[coalesce(tryGet(requestContext().identity, 'claims', 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/role'), '')]",
  "equals": "admin"
}
```
