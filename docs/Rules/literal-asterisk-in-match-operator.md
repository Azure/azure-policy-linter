# Literal Asterisk in Match Operator

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | literal-asterisk-in-match-operator | Warning | default |

## Description

The Azure Policy [`match`, `notMatch`, `matchInsensitively`, and `notMatchInsensitively` operators](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#conditions) treat `#` as a digit placeholder, `?` as a letter placeholder, and `.` as an any-character placeholder. An asterisk (`*`) is matched literally, so it does not provide wildcard matching with these operators.

## Suggestions

- Keep the match-family operator unchanged when `*` should match a literal asterisk.
- Replace `*` with the supported `#`, `?`, or `.` placeholders when they express the required match.
- Consider [`like` or `notLike`](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#conditions) when `*` should match a sequence of characters. These operators use different wildcard syntax, so other match placeholders become literal characters.

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
