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

1. Check for an existing global install before touching anything. List installed tools and find any that provides the `policylinter` command or whose id ends in `.PolicyLinter.Cli`:

   ```
   dotnet tool list -g
   ```

   `dotnet tool` doesn't record where a tool came from, so you can't tell a local build from a feed install by inspection. Record the id and version. Unless the current task already said it's fine to overwrite an existing install, show the user the id and version, tell them it will be removed, and ask whether it's a real install from a feed (restore it afterwards) or a disposable local build (don't). Wait for confirmation.

2. Uninstall the existing tool (repeat for the new id too, if it differs):

   ```
   dotnet tool uninstall -g <existing-id>
   ```

3. Pack and install the CLI as a global tool from a clean build:

   ```
   dotnet pack src/PolicyLinter.Cli/PolicyLinter.Cli.csproj --configuration Release -o <output-path>
   dotnet tool install -g Microsoft.Azure.Policy.PolicyLinter.Cli --add-source <output-path> --no-cache
   ```

4. List the available rule sets to confirm rule discovery works:

   ```
   policylinter --list-rule-sets
   ```

5. Create a temporary policy file. The deny-VM example below triggers a default rule (`HardCodedEnforcementPolicyEffect`), which gives you a guaranteed finding to confirm the CLI ran end-to-end. Adjust the policy to exercise the change you just made - the simplest valid policy that triggers the affected rule is ideal.

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

6. Run the linter under each scenario relevant to the change. At minimum, run the default rule set. If the change touches a non-default rule set or rule-set filtering, run those too:

   ```
   policylinter sanity-check.json
   policylinter sanity-check.json --rule-set <RuleSetName>
   policylinter sanity-check.json --rule-set <RuleSetName> --rule-set default
   ```

7. For each run, verify:
   - The CLI exits without an error.
   - Findings from the rule you changed appear (or are absent) as expected.
   - No findings appear from rule sets that weren't selected.

8. Clean up:
   - Delete the temporary file: `Remove-Item sanity-check.json`.
   - Uninstall the sanity-check build: `dotnet tool uninstall -g Microsoft.Azure.Policy.PolicyLinter.Cli`.
   - If step 1 found a feed install to restore, reinstall it: `dotnet tool install -g <id> --version <version>`.

## What this skill is not

- Not a replacement for unit tests. Unit tests exercise rule logic against precise inputs; this confirms end-to-end glue.
- Not a coverage tool. The test policy is intentionally minimal - pick one that exercises the change you're verifying.
