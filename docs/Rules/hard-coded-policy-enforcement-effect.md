# Hard-Coded Enforcement Policy Effect


| Category | Identifier |
|----------------|----------------------------------------|
| BestPractices | hard-coded-policy-enforcement-effect |

## Description

It is best practice to have the policy effect parameterized. Especially when it comes to enforcement policies. Having the policy effect is determined by a parameter has the following advantages:
- The policy definition can be reused both for enforcement (e.g. when the effect parameter is set to `deny`) and for compliance (the policy effect set to `audit`) scenarios.
- It makes it easier to assign the policy with an audit effect first, observe the compliance data and then gradually transition it to the enforcement effect.

### Suggestions

Use a parameterized effect for the policy. The effect parameter should have a non-enforcement default value, as well as specific allowed values.
For example, for a `deny` policy, the effect parameter should have a default value of `audit` (or no default value at all) and allowed values of `audit`, `deny` and `disabled`.