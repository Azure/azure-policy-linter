# Risky Effect Parameter Default Value


| Category | Identifier |
|----------------|----------------------------------------|
| BestPractices | risky-effect-parameter-default-value |

## Description

The policy effect is parameterized, but the parameter has an enforcement effect (e.g. `deny`) as its default value.
This is risky because it means that the policy will have an enforcement effect by default. Users who assign the policy might not expect this behavior.

### Suggestions

Set the default value of the policy effect parameter to an audit or disabled effect (`audit`, `auditIfNotexists` or `disabled`).