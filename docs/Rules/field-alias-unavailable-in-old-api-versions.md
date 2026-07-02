# Field Alias Unavailable In Old API Versions


| Category | Identifier |
|----------------|----------------------------------------|
| ResourceFields | field-alias-unavailable-in-old-api-versions |

## Description

The policy definition is referencing a [field alias](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/definition-structure-alias) that maps to a property that doesn't exist in older API versions of the targeted resource type.
Aliases are meant to map a property path across ALL available API versions of a resource. However, it is very common for resource properties to be available only starting from the API version in which they were introduced.
When a property is added to a new API version, it can't be added to older versions since it is considered a breaking change.

This is typically not a problem for policies that are only used for [compliance reporting](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/compliance-states) since the compliance scan is using the latest API version available for the resource, which will typically have the targeted resource properties.
However, this can be a problem for enforcement policies (e.g. policies with `deny` effect) which are evaluated against incoming requests which can use any available API version for the resource. When a request is using an API version in which an alias doesn't exists, the alias will be resolved into an empty value, which might result in unexpected enforcement behavior.

This is a very common pitfall of enforcement policies:
- Policy authors typically write their policy based of the latest API version of the target resource.
- Policy authors are often unaware of the implications of their policy on requests using older API versions, and how many users in their environment might be affected by it.
- The default behavior of the property in older API versions might not be well-defined, or may make it hard to write an effective policy. Deciding what to do with old API versions might not be trivial.

> Note: The fact that this issue doesn't affect enforcement increases the risk since policy authors might see "green" compliance and think that everything is OK.

> Note: These issues are common for all cases where a property might be missing from an evaluated incoming request.

### Suggestions

- Verify that the field is indeed unavailable in the API versions returned by the linter.
- Confirm the default value the resource provider will set to the property when handling requests using old API versions. This can be done by reading docs or trial and error.
- Decide what is the desired policy outcome in the case the property is missing.
  - If deciding not to enforce, use `exists` condition in the policy rule (which will apply to all cases where the property might be missing). Alternatively, consider using the `[requestContext().apiVersion]` function in the policy rule to explicitly determine what to do in the case of old API versions.
  - If deciding to enforce, the main goal is to identify cases where an old API version is used and whether it's possible for callers to move to the latest API version.
    - Test the policy against common Azure clients (portal, PS, CLI) to ensure their latest version contains the property.
    - Assign the policy with `audit` effect and inspect the [activity logs](https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log-schema#policy-category) for audit events, which will also contain the request details.
    - Things to look for in activity logs:
      - Number of audited requests caused by usage of old API version. Large number might indicate that the policy has false-positives and in any case, it might not be safe to apply an enforcement policy while these requests are ongoing.
      - Clients that are making the requests. If there are apps making calls on behalf of users, it might be impossible for users to control the payload used by the tool that is making the request.

## Data sources

- Resource metadata is derived from the public [Azure REST API specs](https://github.com/Azure/azure-rest-api-specs/tree/main/specification).
- The linter repo contains a dump of all available policy aliases **from the public cloud**.
