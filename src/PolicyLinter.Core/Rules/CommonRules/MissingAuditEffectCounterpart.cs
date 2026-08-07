// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;

    /// <summary>
    /// Detects parameterized policy effects that include enforcement effects without their
    /// corresponding audit effects.
    /// </summary>
    public sealed class MissingAuditEffectCounterpart : LinterRule<ThenExpression>
    {
        private const string RuleTitle = "Missing Audit Effect Counterpart";

        private const string RuleDescription =
            "The effect parameter '{0}' allows the enforcement effects '{1}' but not their audit counterpart '{2}'. " +
            "Adding '{2}' lets an assignment audit the policy before enforcing it.";

        private static readonly IReadOnlyDictionary<string, string> EnforcementToAuditCounterpartMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { "deny", "audit" },
            { "modify", "audit" },
            { "append", "audit" },
            { "deployIfNotExists", "auditIfNotExists" },
            { "denyAction", "auditAction" },
        };

        /// <summary>
        /// Initializes a new instance of the <see cref="MissingAuditEffectCounterpart"/> class.
        /// </summary>
        public MissingAuditEffectCounterpart() : base(
            identifier: "missing-audit-effect-counterpart",
            category: Category.BestPractices,
            title: MissingAuditEffectCounterpart.RuleTitle,
            descriptionFormat: MissingAuditEffectCounterpart.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(ThenExpression expression, LinterContext context)
        {
            if (!expression.Effect.HasSimpleParameterizedValue(
                context: context,
                out var parameterName,
                out var allowedValues,
                out _))
            {
                return Array.Empty<LinterOutput>();
            }

            if (allowedValues == null || allowedValues.Length == 0)
            {
                return Array.Empty<LinterOutput>();
            }


            if (context.Parameters == null ||
                !context.Parameters.TryGetValue(parameterName, out var parameter))
            {
                return Array.Empty<LinterOutput>();
            }

            var allowedValuesSet = new HashSet<string>(allowedValues, StringComparer.OrdinalIgnoreCase);
            var encounteredEnforcementEffects = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var auditCounterparts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var allowedValue in allowedValues)
            {
                _ = allowedValuesSet.Add(allowedValue);
                if (MissingAuditEffectCounterpart.EnforcementToAuditCounterpartMap.TryGetValue(key: allowedValue, out var auditCounterpart))
                {
                    _ = encounteredEnforcementEffects.Add(allowedValue);
                    _ = auditCounterparts.Add(auditCounterpart);
                }
            }

            if (auditCounterparts.Count == 1 && allowedValuesSet.All(allowedValue => encounteredEnforcementEffects.Contains(allowedValue)))
            {
                var requiredAuditCounterpart = auditCounterparts.First();
                return new[]
                {
                    this.CreateWarning(expression: parameter, parameterName, string.Join(',', encounteredEnforcementEffects), requiredAuditCounterpart),
                };
            }

            // The effect parameter allowed values either has no enforcement effects,
            // or it's mixing mismatching enforcement effects (e.g. "deny" and "deployIfNotExists"),
            // or mismatching enforcement/audit counterparts (e.g. "deny" and "auditIfNotExists"),
            // or it has values representing unknown policy effects (e.g. "deny" and "foo").
            return Array.Empty<LinterOutput>();
        }
    }
}
