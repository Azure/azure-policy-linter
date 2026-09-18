---
name: triage-linter-results
description: 'Assess Policy Linter findings against an Azure Policy definition, separate contextually relevant findings from noise, aggregate related output, and suggest probable fixes. Use whenever a user asks which linter findings matter, whether linter warnings are noisy, how to address Policy Linter output, or wants structured findings suitable for PR comments. Accepts JSON or console output; this is not a review of linter rule code.'
---

# Triage Policy Linter Results

Assess one policy definition and its Policy Linter results. Return only JSON conforming to `references/output.schema.json`.

When the Azure Policy Linter repository is available, read `docs/linter-rule-design.md` and only the `docs/Rules/` files for rule identifiers in the selected results. In another repository, use each selected result's `documentationUrl` when accessible. If rule documentation is unavailable, rely on the finding text and policy evidence, lower confidence where necessary, and do not invent rule-specific behavior.

## Flow

1. Select exactly one result set. Preserve the selected JSON key exactly, including when the result has only one key. For multi-file JSON or console output, require a unique normalized source-path match; never guess by filename, policy name, or finding content. Console output loses severity and category, so do not infer them and mark the result `partial`.
2. Treat a Critical finding as `system_failure` and block normal triage because rule evaluation may be incomplete. Other `system-rule` findings influence `context` but are not triaged as policy issues. Set `policyShape` to `resource` when the supplied root contains the policy under `properties`; use `property_bag` only when `policyRule` is at the supplied root. An empty result means only that the invoked rules emitted nothing.
3. Resolve every selected finding's dotted `path` against the policy exactly as supplied, accounting for the synthetic `properties` prefix on property-bag input. Never repair, approximate, or invent a location. If a path does not resolve, group it as `investigate`, explain that current matching results are required, and mark the result `partial`.
4. Resolve the effect contract before judging findings. A literal effect is both `defaultEffect` and the sole allowed value. For a constrained parameter, use its default and sorted allowed values. For a parameter without usable `allowedValues`, use `"any"` and `enforcementPossible: true`. Enforcement is possible when an allowed effect can deny, modify, or deploy.
5. Read the whole policy behavior, not only the reported condition. Reconcile `if` with Modify operations, deployment resources, `existenceCondition`, parameter defaults, guards, and stated purpose before dismissing a finding. In particular:
   - An `exists` or `empty` test already defines missing-property behavior; decide whether that outcome is appropriate.
   - A read-only alias warning concerns request-time availability during enforcement, not whether the policy tries to modify that field.
   - Trace missing collections through the actual count or quantifier. An absent collection that counts as zero is normally harmless when the policy only restricts members that are present; do not call it generic fail-open behavior.
   - Optional and old-API aliases matter more when absence can deny a request, skip remediation, defeat an exemption, or prevent convergence. When Deny is allowed and an unavailable alias is used by a negative or `exists: false` test, require a choice or investigation unless the affected API versions are explicitly excluded.
   - An enforcement default or hard-coded effect can be `none` when it is explicit, appropriate to the policy's purpose, and assignment already requires deliberate inputs or the policy's role requires mandatory enforcement. Do not propose Audit for Modify-only logic or when request-only expressions make Audit uninformative.
   - Treat a wildcard-free `like` as an edit only after confirming that an exact match, rather than a missing wildcard, is intended.
6. Deduplicate exact `(ruleIdentifier, severity, path, description)` emissions while retaining every zero-based source index. Aggregate only when one consequence, decision, and recommendation covers every member. Keep separate edits at separate anchors and separate detection, remediation, exemption, and assignment-contract consequences.
7. Use `direct_edit` only for a semantics-preserving change determined by the policy. Changes to API gates, assignment parameters, defaults, allowed values, resource scope, or customer-managed values require `choice_required`. Use `investigate` only for a specific unanswered fact; use `none` when no change or investigation follows. Include the smallest existing RFC 6901 edit anchors only for `direct_edit` and `choice_required`.
8. Sort groups by decision (`direct_edit`, `choice_required`, `investigate`, `none`) and then lowest source index. Account for every source index exactly once and return no prose outside the JSON document.
