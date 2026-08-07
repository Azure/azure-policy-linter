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
            "The effect parameter '{0}' allows the enforcement effect '{1}' but not its audit counterpart '{2}'. " +
            "Adding '{2}' lets assignments use non-enforcing behavior without changing the policy definition.";

        private static readonly (string Counterpart, string[] EnforcementEffects)[] CounterpartMappings =
        {
            ("audit", new[] { "deny", "modify", "append" }),
            ("auditIfNotExists", new[] { "deployIfNotExists" }),
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

            var allowedValueSet = new HashSet<string>(allowedValues, StringComparer.OrdinalIgnoreCase);

            if (context.Parameters == null ||
                !context.Parameters.TryGetValue(parameterName, out var parameter))
            {
                return Array.Empty<LinterOutput>();
            }

            return MissingAuditEffectCounterpart.CounterpartMappings
                .Where(mapping => !allowedValueSet.Contains(mapping.Counterpart))
                .Select(mapping => new
                {
                    mapping.Counterpart,
                    EnforcementEffect = mapping.EnforcementEffects.FirstOrDefault(allowedValueSet.Contains),
                })
                .Where(mapping => mapping.EnforcementEffect != null)
                .Select(mapping => this.CreateInformational(
                    expression: parameter,
                    parameterName,
                    mapping.EnforcementEffect!,
                    mapping.Counterpart))
                .ToArray();
        }
    }
}
