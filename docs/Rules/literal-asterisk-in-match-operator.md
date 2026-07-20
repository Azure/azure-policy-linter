# Literal Asterisk in Match Operator

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | literal-asterisk-in-match-operator | Warning | default |

## Description

The Azure Policy [`match`, `notMatch`, `matchInsensitively`, and `notMatchInsensitively` operators](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#conditions) treat `#` as a digit placeholder, `?` as a letter placeholder, and `.` as an any-character placeholder. An asterisk (`*`) is matched literally, so it does not provide wildcard matching with these operators.

## Suggestions

- Use `like` or `notLike` instead when `*` should match any sequence of characters.
- Keep the match-family operator only when the compared value must contain a literal asterisk.

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
