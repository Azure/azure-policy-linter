# Policy Rule References Multiple Resource Types

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | policy-rule-references-multiple-resource-types | Informational | — |

## Description

The policy references multiple resource types, which can broaden the set of resources it evaluates. This can be intentional; the finding is informational so the author can confirm the scope.

## Suggestions

- If the multiple types are intentional (for example, governing tags or locations across multiple resource types), no change is needed.
- If a single resource type was intended, narrow the `if` to that type and group per-type policies together in an initiative.
