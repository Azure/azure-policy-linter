# Literal Asterisk in Match Operator

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | literal-asterisk-in-match-operator | Warning | default |

## Description

This rule reports a match-family condition whose value contains an asterisk (`*`). The [`match`, `notMatch`, `matchInsensitively`, and `notMatchInsensitively` operators](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#conditions) match `*` literally, so it does not act as a wildcard. Their placeholders are `#` for a digit, `?` for a letter, and `.` for any character.

## Suggestions

- Replace `*` with the supported `#`, `?`, or `.` placeholders when they express the required match.
- Consider [`like` or `notLike`](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#conditions) when `*` should match a sequence of characters. Note that these operators use different wildcard syntax.

## Examples

### Violation

```json
{
  "field": "name",
  "match": "vm-*"
}
```

### Correct

```json
{
  "field": "name",
  "like": "vm-*"
}
```
