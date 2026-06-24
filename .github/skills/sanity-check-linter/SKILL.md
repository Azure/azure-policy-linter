---
name: sanity-check-linter
description: 'Run the Policy Linter CLI against a temporary test policy to confirm a recent code change behaves end-to-end. Triggers: "sanity check the linter", "run the linter against a test policy", "verify the linter still works", "smoke test the linter".'
---

# Skill: Sanity-Check the Policy Linter

Run the linter CLI against a temporary policy to confirm a code change is structurally sound end-to-end before committing. This is distinct from unit tests - it verifies rule discovery, dispatch, rule-set filtering, and output formatting.

## When to use

- After adding a new linter rule.
- After modifying the engine, expression model, or rule dispatch.
- Before declaring a non-trivial change complete.

Not needed for doc-only changes, test-only changes, or version bumps.

## Flow

1. List the available rule sets to confirm rule discovery works:

   ```
   policylinter --list-rule-sets
   ```

   When running from source, use `dotnet run -- --list-rule-sets` from the relevant CLI project directory.

2. Create a temporary policy file. The deny-VM example below triggers a default rule (`HardCodedEnforcementPolicyEffect`), which gives you a guaranteed finding to confirm the CLI ran end-to-end. Adjust the policy to exercise the change you just made - the simplest valid policy that triggers the affected rule is ideal.

   ```powershell
   @"
   {
     "properties": {
       "policyType": "Custom",
       "mode": "All",
       "displayName": "Sanity-check policy",
       "description": "Temporary policy for linter sanity-check.",
       "policyRule": {
         "if": { "field": "type", "equals": "Microsoft.Compute/virtualMachines" },
         "then": { "effect": "deny" }
       }
     }
   }
   "@ | Out-File -FilePath sanity-check.json -Encoding UTF8
   ```

3. Run the linter under each scenario relevant to the change. At minimum, run the default rule set. If the change touches a non-default rule set or rule-set filtering, run those too:

   ```
   policylinter sanity-check.json
   policylinter sanity-check.json --rule-set <RuleSetName>
   policylinter sanity-check.json --rule-set <RuleSetName> --rule-set default
   ```

4. For each run, verify:
   - The CLI exits without an error.
   - Findings from the rule you changed appear (or are absent) as expected.
   - No findings appear from rule sets that weren't selected.

5. Delete the temporary file:

   ```powershell
   Remove-Item sanity-check.json
   ```

## What this skill is not

- Not a replacement for unit tests. Unit tests exercise rule logic against precise inputs; this confirms end-to-end glue.
- Not a coverage tool. The test policy is intentionally minimal - pick one that exercises the change you're verifying.
