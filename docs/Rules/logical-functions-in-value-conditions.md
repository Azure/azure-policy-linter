# Logical Functions in Value Conditions

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | logical-functions-in-value-conditions | Informational | default |

## Description

Complex conditions folded into template functions (`and()`, `or()`, `not()`, or `if()`) instead of using native policy conditions (`allOf`, `anyOf`, and `not`) are hard to read and debug.
Compliance details show the full expression and its result (e.g. `true`), but not the results of the individual field checks.

Using these template functions can be useful to:

- Keep expression-based guards that [prevent template failures](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#avoiding-template-failures) from invalid function calls or property selection.
- Preserve intentional type conversions and case-sensitive comparisons when moving checks out of a `value` expression.

But for most cases, using the native policy conditions is preferred.

## Suggestions

- Express separate conditions with [`allOf`, `anyOf`, and `not`](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#logical-operators) whenever possible.
