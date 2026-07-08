---
name: Linter rule suggestion
about: Suggest a new linter rule, or a change to an existing one.
title: "<short descriptive title>"
labels: ["rule-suggestion"]
---

<!--
Use this for a new rule ("the linter should flag pattern X") or to refine an existing
rule (change its severity, message, or when it fires). If an existing rule is instead
malfunctioning - firing on a clearly-valid policy, missing a case it should catch, or
crashing - that's a bug; use the Bug report template. If the linter *cannot inspect or
express* what you need (a policy shape it doesn't model), that's a feature gap; use the
Feature gap template.

Fill in what you know; leave a field as TBD (not yet decided) or None (decided: nothing
to add) rather than guessing. The fields below match the linter's rule spec, so a
complete suggestion can be picked up and implemented directly.
-->

**Existing rule**
<!-- If this refines an existing rule, give its identifier (e.g. hard-coded-policy-enforcement-effect). Leave blank for a new rule. -->

**Summary**
<!-- 1-2 sentences: what is checked and how it affects the policy's behavior. For a change, what should differ from today. -->

**Target**
<!-- What part of the definition the rule inspects (e.g. field references, parameters, policyRule.if conditions, the effect). -->

**Applicability**
<!-- When the rule fires and when it stays silent, stated concretely enough to become a boolean.
     e.g. "control-plane policy whose effect is parameterized and one allowed value is deployIfNotExists". -->

**Required context / data**
<!-- Anything beyond the policy JSON the rule needs (e.g. "whether the referenced field is readonly"), or "Policy JSON only". -->

**Additional details**
<!-- Extra dimensions the summary can't carry: multiple manifestations, special cases, how each is treated. Or "None". -->

**Correct example**
<!-- Minimal policy snippet that should pass. "N/A" if an example adds no signal. -->
```json

```

**Violation example**
<!-- Minimal snippet that should trigger the rule, plus a one-line note on why. -->
```json

```

**Suggested severity / category**
<!-- e.g. severity Error / Warning / Informational; category BestPractices / ResourceFields / Misc. Or TBD. -->

**Suggested rule set**
<!-- e.g. default, or a non-default set name. Or TBD. -->

**Open questions**
<!-- Anything the implementer needs to decide, or "None". -->

**References**
<!-- Links worth including in the rule's documentation, or "None". -->
