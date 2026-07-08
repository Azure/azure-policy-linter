# Optional Field Alias


| Category | Identifier |
|----------------|----------------------------------------|
| ResourceFields | optional-field-alias |

## Description

The policy definition is referencing a [field alias](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/definition-structure-alias) that maps to a property that is annotated as optional (more accurately: it's not annotated as "required") by resource provider in one or more API versions. This means that this property might not exist in all incoming requests for the resource types which might result in incorrect or unexpected evaluation results.

### Suggestions

- Consult the resource provider documentation to determine the API behavior when the property is missing. This also might require trial and error.
- Decide what is the desired policy outcome in the case the property is missing.
  - If deciding not to enforce, add an `exists` condition to the policy rule.
  - If deciding to enforce, identify how often the property is expected to be missing in incoming requests, and whether it is acceptable.
    - Test the policy against common Azure clients (portal, PS, CLI) to ensure their latest version contains the property.
    - Assign the policy with `audit` effect and inspect the [activity logs](https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log-schema#policy-category) for audit events, which will also contain the request details.
    - Things to look for in activity logs:
      - Number of audited requests caused by the property being missing. Large number might indicate that the policy has false-positives and in any case, it might not be safe to apply an enforcement policy while these requests are ongoing.
      - Clients that are making the requests. If there are apps making calls on behalf of users, it might be impossible for users to control the payload used by the tool that is making the request.

## Data sources

- Resource metadata is derived from the public [Azure REST API specs](https://github.com/Azure/azure-rest-api-specs/tree/main/specification).
- The linter repo contains a dump of all available policy aliases **from the public cloud**.
