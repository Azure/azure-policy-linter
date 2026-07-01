---
name: Bug report
about: Report incorrect linter behavior - a crash, bad output, or a rule firing on a valid policy or missing a case.
title: "<short description>"
labels: ["bug"]
---

<!--
Use this when the linter does the wrong thing: it crashes, produces bad output, or a
rule fires on a clearly-valid policy (false positive) or misses a case it should catch
(false negative).

To instead change a rule's severity, message, or when it should fire (a judgment call,
not a malfunction), use the Linter rule suggestion template.

The single most useful thing you can provide is a minimal policy that reproduces the
problem - please trim it to the smallest definition that still shows the issue.
-->

**Rule identifier**
<!-- If the problem is with a specific rule, its identifier (e.g. hard-coded-policy-enforcement-effect). Leave blank if not rule-specific. -->

**Reproducing policy**
<!-- The smallest policy definition JSON that reproduces the problem. -->
```json

```

**Command**
<!-- The exact command you ran, e.g. policylinter policy.json --rule-set default -->

**Expected behavior**
<!-- What you expected the linter to do. -->

**Actual behavior**
<!-- What the linter actually did. Paste the relevant output or error. -->

**Version**
<!-- Output of `policylinter --version`, or the commit SHA if you built from source. -->

**Operating system**
<!-- Windows / Linux / macOS. -->
