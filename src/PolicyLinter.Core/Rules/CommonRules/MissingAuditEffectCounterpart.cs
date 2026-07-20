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
            "The effect parameter '{0}' is missing these audit counterparts from its allowedValues: {1}. " +
            "Adding them lets assignments use non-enforcing behavior without changing the policy definition.";

        private static readonly (string Counterpart, string[] EnforcementEffects)[] CounterpartMappings =
        {
            ("audit", new[] { "deny", "modify", "append" }),
            ("auditIfNotExists", new[] { "deployIfNotExists" }),
            ("auditAction", new[] { "denyAction" }),
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

            var missingCounterparts = MissingAuditEffectCounterpart.CounterpartMappings
                .Where(mapping =>
                    mapping.EnforcementEffects.Any(allowedValueSet.Contains) &&
                    !allowedValueSet.Contains(mapping.Counterpart))
                .Select(mapping => mapping.Counterpart)
                .ToArray();

            if (missingCounterparts.Length == 0)
            {
                return Array.Empty<LinterOutput>();
            }

            var missingCounterpartList = $"'{string.Join("', '", missingCounterparts)}'";

            return new[]
            {
                this.CreateInformational(
                    expression: expression.Effect,
                    parameterName,
                    missingCounterpartList),
            };
        }
    }
}
