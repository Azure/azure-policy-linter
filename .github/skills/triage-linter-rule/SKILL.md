---
name: triage-linter-rule
description: 'Turn a vague "this could be a linter rule" idea into one or more concise specs for the Azure Policy Linter. Output is a spec, saved as a local Markdown file or handed off to the authoring skill. Triggers: "this could be a linter rule", "lint rule for this", "draft a linter rule", "policy linter idea", "spec a linter rule".'
---

# Policy Linter Rule Triage

Help the user go from a fuzzy idea to one or more concise **specs**, each describing a single linter rule. Output is a spec describing the desired rule, not an implementation of the rule itself.

**Reference:** `docs/linter-rule-design.md` is the canonical doc on what makes a good rule (scope, severity, naming, description conventions). Use it as the source of truth when filling spec fields and when judging fit.

## What the Policy Linter is

The policy linter scans **policy definitions** for quality issues. Its purpose is to capture unwritten knowledge: gotchas with policy primitives, common authoring mistakes, and known issues with how policy interacts with specific resource types or fields. It ships a common rule set plus custom rule sets for scenario-specific rules.

For deeper context, see `docs/linter-rule-design.md`.

## In scope / out of scope

A linter rule is appropriate when it captures one of:
- A policy authoring best practice.
- A missed edge case the author probably didn't think about.
- A known issue or gotcha with a specific policy primitive, pattern, resource type, or resource field.
- Invalid policy syntax that the service won't catch cleanly (e.g. a parameter reference to an undefined parameter).

And it's valuable to the author - by suggesting a fix, flagging an edge case worth testing, or surfacing a platform limitation that will affect the policy.

It is **not** a linter rule when:
- The check is non-deterministic (e.g. "the description must accurately describe the policy's behavior").
- It needs online data, identity, or tenant/environment-specific information.

If the idea doesn't fit, say so plainly. Don't push back if the user still wants to continue - capture the spec anyway and note the concern.

## What makes a good rule

- **Useful to a policy author.** The rule's purpose is to help an author do something concrete about a problem in their policy. The finding should leave them knowing what was found, why it matters for their policy, and what to do about it. A rule that doesn't pass this test isn't a rule.
- **Targeted.** The rule has well-defined applicability and prerequisites - it knows exactly when it should fire and when it shouldn't. Example: a rule suggesting that `deployIfNotExists` policies also offer `auditIfNotExists` as an effect choice should only fire when the effect is parameterized; if the effect is a hardcoded `deployIfNotExists`, that's a different rule's job (e.g. one that recommends parameterizing the effect in the first place).
- **Specific.** Each rule checks exactly one thing.

`docs/linter-rule-design.md` expands on each of these.

## Flow

Don't dump the whole template at once.

If you're running without an interactive user - called from another agent, batch context - don't loop on confirmations. Make the call, log the rationale in your scratchpad, and proceed. Surface the decisions in the final spec output so the next consumer can override.

1. **Capture** the raw idea in the user's words. If it came from a PR, link or quote the relevant snippet.
2. **Check for existing rules.** Start by scanning the rule doc filenames (each matches a rule identifier) for hints; drill into the doc bodies for any that look like a match. If an existing rule already covers the scenario, surface it and ask whether the new idea is redundant. If you find a partial overlap or an issue in an existing rule, ask whether the user wants to pivot to a spec for updating that rule instead.
3. **Probe for missing details.** If the idea is shaky, ask what would sharpen it: a spec, a policy example in the repo, official Policy or Azure REST API docs (if this is about specific resource types). Ask the user whether they want you to do any research and whether they have sources for you. Don't research unprompted - Research pointers below is the "where to look when asked" reference.
4. **Consider generalization.** The user's prompt might name a specific primitive or resource type but actually describe a pattern that applies more broadly. If you suspect that, surface it and ask before widening the scope.
5. **Gate against scope.** If out of scope, say so plainly and explain. If the user wants to continue anyway, capture the spec and note the concern - don't push back further.
6. **Decompose and share the breakdown.** One idea often hides multiple rules (e.g. "tags should be consistent" -> naming, casing, required keys). Split when warranted, then walk the user through the proposed rules and how together they cover the original idea. Call out that one-rule-one-check is the norm. If the user wants a different split - or to keep it as one rule - and has a reason, go with it.
7. **Draft, then refine.** For each rule, fill the spec fields below with what you know or can **reasonably** infer; leave gaps blank rather than guess. Walk the user through the draft, fill the gaps, and address feedback. Be especially careful not to add tone, content, or opinions that change what the user actually meant.
8. **Confirm and hand off.** See *Handoff* below.

## Spec fields (per rule)

Walk the user through the draft in tiers - never dump the whole template at once. Land Core first, then sweep through Optional only where there's real signal.

### Core - the rule's essence

- **Title** - short, imperative. e.g. "Warn when `field` targets a readonly property".
- **Summary** - 1-2 sentences: what's being checked and how it affects the behavior of the policy.
- **Target** - what part of the definition the rule inspects (e.g. field references, parameters, `policyRule.if` conditions, template function calls).
- **Applicability** - a predicate describing when the rule fires and when it stays silent. State it concretely enough that an implementer could turn it into a boolean. This also helps surface gaps in linter context fields and utility methods.
  - Example: *"control-plane policy whose `effect` is parameterized and one of the allowed values is `deployIfNotExists`."*
- **Required context / data** - anything beyond the policy JSON the rule needs to make its decision (e.g. "whether the referenced resource field is readonly", "the resource type's latest API versions"). No need to verify that the data is available to the linter, just call out what's needed.
- **Additional details** - extra dimensions the Summary can't carry cleanly. Use this when the rule targets a pattern that appears in multiple forms or places: enumerate the manifestations, special cases, and how each should be treated. Leave blank when the Summary already covers everything.
- **Correct example** - minimal policy snippet (or fragment) that should pass. Illustrative, not exhaustive. Prefer one the user supplies; otherwise draft something minimal and confirm it's representative. `N/A` is acceptable when an example would add no signal.
- **Violation example** - minimal snippet that should trigger the rule, with a one-line note on why. Same guidance as above.

### Optional - fill only where there's signal

- **Suggested severity / category** - e.g. severity `Error` / `Warning` / `Informational`; category `BestPractices` / `ResourceFields` / `Misc`. Revisable at implementation time - don't push the user on these.
- **Suggested rule set** - e.g. `default`, or a non-default set name. Revisable at implementation time - don't push the user on this.
- **Open questions** - anything the implementer needs to decide.
- **References** - references that could be included in the rule's documentation.

## Research pointers (use sparingly)

Delegate fetches to a sub-agent.

Official policy structure documentation:
- [Policy definition structure](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/definition-structure-policy-rule)
- [Policy effects](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/effect-basics)
- [Policy parameters](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/definition-structure-parameters)

If the Microsoft Learn MCP server is available, use it to fetch up-to-date official documentation for any policy structure questions (https://learn.microsoft.com/api/mcp).

In-repo references:
- `docs/linter-rule-design.md` - design principles for rules.
- `docs/linter-architecture.md` - engineer-facing reference for the linter's code.
- `docs/Rules/` - existing rule docs; good for tone and depth of spec.
- `README.md` - tool overview.

## Handoff

Once the spec is confirmed, ask the user what to do with it. Two paths:

### 1. Save the spec as a local Markdown file

Render the spec fields into a Markdown file and write it locally for the user to review. Use `TBD` for unfilled values and `None` where applicable, so reviewers can tell the difference between "decided" and "not yet considered":

```
# [Linter rule] <Title from spec>

**Summary**
<summary>

**Target**
<what part of the definition the rule inspects>

**Applicability**
<predicate: when the rule fires, when it stays silent>

**Required context / data**
<external data the rule needs, or "Policy JSON only">

**Additional details**
<extra implementation context, or "None">

**Correct example**
```json
<correct>
```

**Violation example** - <one-line why>
```json
<violation>
```

**Suggested severity / category**
<value or TBD>

**Suggested rule set**
<value or TBD>

**Open questions**
<list or "None">

**References**
<links or "None">
```

If the user is spec'ing multiple rules from one idea, write one Markdown file per rule.

> Note: filing the spec directly as a GitHub issue is not yet supported. For now this skill only produces local Markdown files. A future update should add a handoff that opens a GitHub issue from the spec.

### 2. Proceed directly to implementation

Hand the spec off to the authoring skill (or pass it back to the user verbatim for them to drive).

Default to asking - don't write a file or begin implementation without explicit confirmation.

## Hard rules for this skill

- Output is a **spec**, never an implementation.
- Don't search the linter codebase for conventions - convention-matching happens at implementation time. (Looking up existing rules to check for overlap is fine and expected; see the Flow.)
- Don't invent taxonomy values (severity, category, rule set names) the user hasn't given you. Leave `TBD`.
- Don't add content, tone, or opinions that change the meaning of the user's idea. When in doubt, ask.
- Don't push back when the user overrides your suggested breakdown or scope, as long as they've given a reason.
