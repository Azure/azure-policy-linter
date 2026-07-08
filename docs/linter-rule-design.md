# Designing a Policy Linter Rule

This guide describes the experience the Policy Linter aims to give its users, and how to design linter rules to deliver it. It covers scope, severity, naming, failure messages, and documentation, and is written for engineers and AI agents that draft, review, or triage linter rules.

## What the linter is for

The Policy Linter inspects policy definitions and reports quality issues. Its core value is capturing unwritten knowledge: gotchas with policy primitives, common authoring mistakes, and known issues with how policy interacts with specific resource types or fields. It ships a common rule set that applies to all policies, and supports custom rule sets for scenario-specific rules (for example, conventions that only apply to built-in policy definitions).

The policy definitions REST API already validates the schema, expressions, and structure of a definition. Rules that re-check things the API rejects are allowed - but they are secondary to the linter's purpose. The API's job is to reject invalid policies; the linter's job is to flag valid policies that have problems anyway.

The linter does not reason across multiple policies, query the tenant, or evaluate against live resources. Each rule sees one policy definition at a time and decides from its JSON plus the metadata and context the linter makes available to rules.

### Representative rule examples

- **Best practices** - suggest parameterizing the policy effect.
- **Resource type metadata gotchas** - warn when a policy references immutable or readonly fields, since this affects enforcement behavior.
- **Improved readability** - suggest collapsing redundant quantifiers (for example, an `allOf` containing only another `allOf`).
- **Policy language gotchas** - warn when the `match` operator's value contains wildcards (`*`), since they're treated as literal characters.
- **Resource-specific behavior** - warn when an enforcement policy targets network security group rules: NSG rules can also be updated by modifying the parent NSG which might require a separate policy.

## Design

### Scope

A rule does one specific check. If one idea covers multiple checks ("use parameterized effect with safe default value" really means parameterized effect + safe default value), it's multiple rules.

A rule has well-defined applicability and preconditions - it knows exactly when it should fire and when it shouldn't. For example, a rule ensuring that a policy with a parameterized effect includes `Disabled` in its allowed values must first check that the effect is parameterized, and exit early if it isn't. It should not also flag that the effect should be parameterized in the first place - that's a separate best practice, captured by a different rule.

The same principle applies when an idea describes two finding flavors with different severities or different remediations - for example, an Error for a structural conflict and an Informational for an adjacent observation. Those are two rules, sharing a target. Each gets its own identifier, title, description, and doc. Users get clean filtering, severities stay mono-typed, and descriptions don't have to branch on which case fired.

### Actionability

Ideally, every finding should give the policy author something to do to address a concrete or potential issue with their policy.
The rule should clearly articulate the issue, it's implications and possible remediations.
When possible, the rule must provide a concrete fix or enhancement to the policy definition to address the issue.
Rules that are more informational in nature (raising awareness to platform limitations, missing edge cases, etc) should be clear about what the author should do to mitigate them.
In the rare cases where a rule is not actionable in any way (e.g. the policy is trying to manipulate free-form objects, which is something the language is bad at), it should also be made clear to the user there's nothing to be done.

### Audience and rule set

By default, a rule should capture a universal best practice or issue - something valuable to anyone authoring a policy. Rules that only apply to a specific scenario (for example, built-in policy standards) belong in their own rule set rather than the default set.

Rule sets aren't a way to categorize rules - they're how environment-specific rules get written and run separately from the universal ones.

### Severity

Every finding gets one of three severities: Error, Warning, or Informational. Severity is chosen when the finding is emitted, not declared on the rule. A rule may emit different severities for different instances of issue it's flagging.

The mapping:

- **Error** - The policy will fail to deploy, fail at evaluation time, violate a hard contract or is going to behave significantly different than what the author intended (e.g. the policy mode is wrong, a existence conditions is always false).
- **Warning** - The policy has problems that will cause it to behave unexpectedly in some cases- logic issues, missed edge cases, known resource type gotchas, misuse of policy operators. Also applicable for surfacing highly valuable best practices (e.g. effect parameterization).
- **Informational** - Worth knowing, not worth a warning. Also fits warning cases that apply to large percentage of policies. Things that if the author ignores will have minimal or no impact on the behavior of the policy.

The CLI prints the different severities in different colors.

### Naming and terminology

A rule has two names: its **identifier** (kebab-case, used in CLI output and as the documentation filename) and its **title** (human-readable phrase, shown when a finding is reported). The documentation file's H1 is the title verbatim - it's the same string, not a separate name. Pick the identifier first; derive the title from it.

The default for titles is a descriptive noun phrase in Title Case that names the detected pattern - `Optional Field Alias`, `Unnecessary Quantifier Wrapper`, `Missing Disabled Effect Allowed Value`. Title Case means every word capitalized except short connectives (`and`, `or`, `of`, `in`, `the`, etc.); even the leading operator name in titles like `Match Without Wildcards` is capitalized. The author hasn't done anything wrong yet at title time; the title describes what was found, not what to do about it. Common qualifier vocabulary: `Unnecessary`, `Redundant`, `Missing`, `Risky`, `Optional`, `Hard-Coded`, `Inconsistent`, `Ambiguous`, `Deprecated`.

The class name is the title's PascalCase form (`OptionalFieldAlias`, `UnnecessaryQuantifierWrapper`). The identifier is the kebab-case form (`optional-field-alias`, `unnecessary-quantifier-wrapper`). All three are mechanical transforms of the same phrase.

Prescriptive titles using `Must`, `MustNot`, `Should`, `ShouldNot`, `DoNot`, `Avoid`, `Use`, `Prefer`, `Require`, `Enforce`, or `Disallow` are acceptable when the rule lives in a non-common rule set, when the descriptive form is awkward or long, or when the descriptive form obscures what the rule checks. Author judgment wins when the default doesn't fit.

Use the vocabulary the policy author already knows. The policy schema, the language reference, and the official Azure Policy docs are the sources of truth - `condition`, `field reference`, `alias`, `effect`, `parameter`, `operator`, `allowedValues`, `defaultValue`, `wildcard`. Do not invent categorizing nouns ("groups", "shapes", "patterns") for things that don't already have names in the domain. If you find yourself coining a term, describe the pattern instead, or pick a name that already exists in the policy documentation.

Internal implementation terms - the names of expression-tree node classes, helper types, evaluation phases - never appear in user-facing names or text. They are for the people writing the rule, not the people reading its findings.

### Description

The description is the line of text the author actually sees when their policy triggers the rule (the `Description` field on the rule's `LinterOutput`, surfaced under the title in CLI output). It is short, concrete, and written in the author's frame of reference.

Open with the construct the rule is talking about, named with the policy's own vocabulary and quoted in single quotes: `"The field alias: '{0}' maps to ..."`. The user is looking at their policy; the description names what they're looking at. Then explain the consequence - what the author should care about, in terms of how their policy will behave or how it will be evaluated. Then, when there's something concrete to do, recommend it: a value to set, an operator to switch to, a property to add. Imperative voice for the recommendation.

Examples and counter-examples:

- "The condition uses the '{0}' operator with value '{1}' which contains no wildcards (* or ?). Use '{2}' for exact matching." - names the construct, explains why it matters for the policy, recommends a fix.
- "The effect parameter '{0}' does not include 'Disabled' in its allowedValues. The 'Disabled' effect enables turning off the policy without removing the assignment as well as disabling a single policy within a policy set" - same shape, the consequence is framed for the author.
- Don't write "The like operator is less efficient when no wildcards are present." The performance characteristic is true and not what the author needs to know; what they need to know is that they probably meant `equals`.
- Don't write "The author probably forgot to declare the parameter." Don't speculate about the author's intent or assign blame. State what was found.

When the description uses `{0}` to substitute a value, make sure the surrounding sentence reads naturally once the real value is dropped in. Read it out loud with a realistic value before shipping.

A description is short. Aim for 150-300 characters; treat 400 as a hard ceiling. No line breaks - the CLI prints it as a single line under the title, and IDE integrations show it as a single tooltip line. No embedded URLs either; the runner is responsible for resolving the rule identifier into a link to the doc page when needed.

When a rule finds two independent problems in the same policy, emit two findings. Do not build a single description out of branching fragments ("missing X" / "missing Y" / "missing X and Y").

The description and the rule's documentation file are complementary, not redundant. The description carries the offender and the actionable specifics; the doc carries the rationale, examples, and longer remediation guidance. Don't paraphrase the doc in the description, and don't expand the description into a paragraph because you didn't trust the doc to carry the weight.

### Documentation

Every rule has a Markdown documentation file. Its filename matches the rule identifier; its first heading matches the rule's title. The file lives alongside the other rule docs in the repo.

The doc has four expected pieces, in this order:

- **A metadata table** at the top showing the rule's category, identifier, severity, and rule set. The reader skims this to triage the finding - they want to know how serious it is and whether they need to opt into a rule set to see it.
- **A description** explaining what the rule checks and why it matters. Two to four sentences. Third-person, declarative ("The `like` operator..."). Written for the policy author who just hit the finding and wants context - not for someone learning the linter.
- **Suggestions** giving concrete remediation guidance. Imperative, second-person ("Replace `like` with `equals`...", "Add an `exists` condition..."). Bulleted when there are multiple steps.
- **Examples**, when they add signal. A minimal "violation" JSON fragment that triggers the rule, and a minimal "correct" fragment that passes - both showing only the relevant property, not a full policy document. Omit examples when the rule's check is self-evident from the description.

When the rule touches a documented Azure Policy concept - an operator, a field reference shape, an effect, a parameter type - link to the official Microsoft Learn page for it. Linking lets the doc stay short while pointing the author at canonical depth, and keeps the rule's doc from going stale when the platform's own docs evolve.

Same tone discipline as failure messages: speak to the author about their policy. Don't speculate about why the author might have made a mistake. State what the rule checks, what's at stake **for the policy author** and what to do.

The depth of the doc should match the depth of the problem. A rule that catches an obvious-once-pointed-out issue (a redundant quantifier, a missing wildcard) deserves a short doc - a few sentences and one example, or no example at all if it's truly redundant. A rule whose remediation involves judgment ("audit first, then enforce", "consult the resource provider documentation to find a stable property") deserves the space to walk through that judgment. Don't pad short docs to look thorough, and don't compress long ones to look tidy.

Don't add a long block of CLI invocation instructions to each doc just because the rule is in a non-default rule set. The metadata table already says which rule set the rule belongs to; how to run the linter is the CLI's documentation problem, not the rule's.
