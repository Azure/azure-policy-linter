# Logical Functions in Value Conditions

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | logical-functions-in-value-conditions | Informational | default |

## Description

A `value` condition uses the `and()`, `or()`, `not()`, or `if()` template function to combine checks. Compliance details show the expression and its final result, for example `true`, but not the result of each check. This makes the policy harder to read and debug.

The template functions are still the correct choice when you need to:

- [Prevent template failures](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#avoiding-template-failures) from invalid function calls or property access.
- Keep a type conversion or case-sensitive comparison that the expression depends on.

## Suggestions

- Replace the template function with the [`allOf`, `anyOf`, or `not`](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#logical-operators) logical operators, unless one of the cases above applies.
