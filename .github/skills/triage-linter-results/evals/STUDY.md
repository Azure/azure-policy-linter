# Triage Linter Results Evaluation

## Purpose

The skill receives one Azure Policy definition and its Policy Linter output. It produces deterministic JSON that:

- separates contextually relevant findings from noise;
- deduplicates exact emissions and aggregates compatible findings;
- distinguishes direct edits, author choices, and external investigation;
- proposes probable fixes without silently changing policy semantics;
- preserves source indexes, linter paths, and policy pointers for automation.

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
