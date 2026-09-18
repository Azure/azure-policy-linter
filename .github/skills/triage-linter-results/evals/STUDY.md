# Triage Linter Results Evaluation

## Purpose

The skill receives one Azure Policy definition and its Policy Linter output. It produces structured JSON that:

- separates contextually relevant findings from noise;
- deduplicates exact emissions and aggregates compatible findings;
- distinguishes direct edits, author choices, and external investigation;
- proposes probable fixes without silently changing policy semantics;
- preserves source indexes and exact edit locations.

## Production corpus

The linter was run against all 2,252 production built-in policies in the sister Policy repository.

| Metric | Result |
| --- | ---: |
| Policies | 2,252 |
| Findings | 3,688 |
| Informational | 2,403 |
| Warning | 1,276 |
| Error | 8 |
| Critical | 1 |
| Findings from the six most common rules | 95.1% |

The corpus established recurring patterns for multiple resource types, optional aliases, old API versions, read-only aliases, assignment defaults, and duplicate emissions.

The linter was run across all 2,252 policies, but the skill was not. The first skill evaluation used curated examples plus one real high-volume built-in policy.

## Evaluation design

Nine scenarios tested mechanical fixes, contextual aliases, policy intent, Critical failures, property-bag input, ambiguous result selection, stale paths, console metadata loss, and a real 39-finding policy.

Three strategies ran five times per scenario:

1. Full skill and schema.
2. Schema without the skill guidance.
3. Baseline without either.

This produced 135 original runs. Another 40 full-skill runs measured targeted refinements.

## Results

| Measure | Original | Refined |
| --- | ---: | ---: |
| Contract all-pass on affected cases | 20/40 (50.0%) | 33/40 (82.5%) |
| Frozen semantic rubric | 28/40 (70.0%) | 29/40 (72.5%) |
| Reviewed sensitivity rubric | 31/40 (77.5%) | 39/40 (97.5%) |
| Schema validity across original full-skill runs | 45/45 (100%) | - |

The sensitivity score corrects two disputed action labels and one recommendation-token matcher without replacing the frozen primary result.

## What improved

- Property-bag shape, pointer translation, and assignment-interface handling.
- Stale paths now produce partial, low-confidence investigations instead of edits.
- Critical engine failures block normal triage.
- Console output preserves unknown severity and category as `null`.
- Literal and parameterized effect contracts are interpreted consistently.
- Evidence and edit-target pointers have tighter deterministic membership rules.

## Remaining limitation

One of five refined intent-sensitive runs merged request-identity availability with an independently actionable unguarded-claim fix. The other four preserved the separate direct `tryGet` edit.

Exact structural repetition is still low because aggregation boundaries, confidence, evidence pointers, and alternatives can vary. Downstream automation should consume the schema and stable item IDs rather than assume repeated analyses are byte-for-byte identical.

## Interpretation

The refined skill is ready for human review. The reviewed semantic result is 39/40 across the eight mechanically gradable cases. The high-volume case was reviewed qualitatively: every run accounted for all 39 findings, retained structural edits and assignment choices separately, and avoided indiscriminate aggregation.

Blind Claude Opus grading was attempted but produced no usable output, so no cross-model semantic result is claimed.

## Broader built-in study

A second study used 24 real production built-ins containing 279 findings per pass. The sample covered simple mechanical fixes, enforcement-sensitive aliases, intent-dependent findings, and mixed policies with as many as 39 findings.

The then-current strict output and a much smaller LLM-facing output each ran three times per policy. This produced 144 outputs.

| Check | Strict output | Small output |
| --- | ---: | ---: |
| Outputs | 72 | 72 |
| Accounted for every source finding | 72/72 | 72/72 |
| Combined exact duplicates | 72/72 | 72/72 |
| Made the expected safe mechanical edits | 33/33 | 33/33 |
| Avoided the scorer's known unsafe combinations | 71/72 | 69/72 |
| Identical grouping in all three runs | 3/24 policies | 2/24 policies |

Four independent qualitative reviews compared the strategies policy by policy. The strict output was better on 11 policies, the smaller output was better on 8, and 5 were ties. Each strategy also produced one run that incorrectly labeled a behavior-changing change as an automatic edit.

The strict schema did not reliably improve judgment or stability. Its useful parts were the explicit effect contract, exact source accounting, deduplication, action labels, and edit locations. Its per-finding repetition, mandatory evidence pointers, IDs, confidence labels, and forced alternative lists added substantial output without a consistent quality gain and sometimes distracted from the policy's complete behavior.

The skill now uses a smaller schema that keeps the useful checks. The reasoning instructions also require comparing the condition with Modify operations, deployments, and existence conditions before dismissing a finding; distinguish read-only request availability from modification; allow intentional enforcement defaults to be non-actionable when assignment is already deliberate; and prevent API-gate or customer-value changes from being labeled semantics-preserving.

## Revised-skill regression

The smaller contract and updated reasoning were rerun three times on the ten policies that exposed the clearest failures. All 30 outputs validated and accounted for every source finding.

The revised skill handled these high-impact cases correctly in all three repetitions:

- remediation that detects a value it never changes;
- a targeted resource type with no matching deployment branch;
- linter paths that do not resolve against the supplied policy;
- a Modify operation whose API gate may precede alias support;
- an intentional hard-coded Deny policy;
- an audit-only policy where absent collections safely count as zero;
- old-API aliases used by Deny-capable negative conditions.

Nine final runs retested the last three instruction changes; all validated and preserved every finding. Decisions about optional nested delegation fields still varied between `choice_required`, `investigate`, and `none`, so the skill should not be treated as deterministic policy truth. The change removes the observed unsafe automatic edits but does not eliminate normal model judgment variance.
