# Policy Rule References Multiple Resource Types

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | policy-rule-references-multiple-resource-types | Informational | — |

## Description

The policy rule's `if` condition references more than one resource type, counting both the types named in non-negated `type` field conditions and the types resolved from field aliases. Types excluded by a negated condition are not counted. Targeting several related types in one policy - for example with `"type": { "in": [...] }` - is a legitimate, documented pattern. This finding is advisory: it surfaces the breadth of the policy so the author can confirm it is intentional rather than an accidental over-match.

## Suggestions

- If the multiple types are intentional (for example, governing tags or locations across multiple resource types), no change is needed.
- If a single resource type was intended, narrow the `if` to that type and group per-type policies together in an initiative.

### Correct (intentional multi-type)

```json
{
  "field": "type",
  "in": [
    "Microsoft.Compute/virtualMachines",
    "Microsoft.Compute/disks"
  ]
}
```
