// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions;

    /// <summary>
    /// Checks that an effect parameter's allowedValues contain only interchangeable effects.
    /// </summary>
    public sealed class EffectAllowedValuesShouldNotMixIncompatibleEffects : LinterRule<ThenExpression>
    {
        private const string RuleTitle = "Effect Allowed Values Should Not Mix Incompatible Effects";
        private const string RuleDescription =
            "The effect parameter '{0}' has allowedValues that combine non-interchangeable effects: {1}. Use only effects that are interchangeable with the policy's 'then.details' configuration; 'Disabled' can be combined with any effect.";

        private const string ModifyDetailsCategory = "ModifyDetails";
        private const string IfNotExistsDetailsCategory = "IfNotExistsDetails";
        private const string ActionDetailsCategory = "ActionDetails";
        private const string AppendDetailsCategory = "AppendDetails";
        private const string ManualDetailsCategory = "ManualDetails";

        // Effects in the same category can use the same 'details' configuration. 'mutate' and
        // 'addToNetworkGroup' are intentionally omitted -- they are dataplane-mode effects that
        // the IsControlPlaneMode check already skips.
        private static readonly Dictionary<string, string> EffectToCategory = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { "Modify", EffectAllowedValuesShouldNotMixIncompatibleEffects.ModifyDetailsCategory },
            { "AuditIfNotExists", EffectAllowedValuesShouldNotMixIncompatibleEffects.IfNotExistsDetailsCategory },
            { "DeployIfNotExists", EffectAllowedValuesShouldNotMixIncompatibleEffects.IfNotExistsDetailsCategory },
            { "DenyAction", EffectAllowedValuesShouldNotMixIncompatibleEffects.ActionDetailsCategory },
            { "AuditAction", EffectAllowedValuesShouldNotMixIncompatibleEffects.ActionDetailsCategory },
            { "Append", EffectAllowedValuesShouldNotMixIncompatibleEffects.AppendDetailsCategory },
            { "Manual", EffectAllowedValuesShouldNotMixIncompatibleEffects.ManualDetailsCategory },
        };

        /// <summary>
        /// Initializes a new instance of the <see cref="EffectAllowedValuesShouldNotMixIncompatibleEffects"/> class.
        /// </summary>
        public EffectAllowedValuesShouldNotMixIncompatibleEffects() : base(
            identifier: "effect-allowed-values-should-not-mix-incompatible-effects",
            category: Category.BestPractices,
            title: EffectAllowedValuesShouldNotMixIncompatibleEffects.RuleTitle,
            descriptionFormat: EffectAllowedValuesShouldNotMixIncompatibleEffects.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(ThenExpression expression, LinterContext context)
        {
            // Skip dataplane policies -- they may use effects not known to this rule.
            if (!EffectAllowedValuesShouldNotMixIncompatibleEffects.IsControlPlaneMode(expression))
            {
                return Array.Empty<LinterOutput>();
            }

            if (!expression.Effect.HasSimpleParameterizedValue(context: context, out var parameterName, out var allowedValues, out _))
            {
                return Array.Empty<LinterOutput>();
            }

            if (allowedValues == null)
            {
                return Array.Empty<LinterOutput>();
            }

            var categorizedEffects = allowedValues
                .Where(v => v != null && EffectAllowedValuesShouldNotMixIncompatibleEffects.EffectToCategory.ContainsKey(v))
                .ToArray();

            var manualCombination = allowedValues
                .Where(predicate: v => v != null && EffectAllowedValuesShouldNotMixIncompatibleEffects.IsKnownNonDisabledEffect(effect: v))
                .Distinct(comparer: StringComparer.OrdinalIgnoreCase)
                .ToArray();

            var hasManualConflict = manualCombination.Length > 1 &&
                manualCombination.Any(predicate: v => string.Equals(a: v, b: "Manual", comparisonType: StringComparison.OrdinalIgnoreCase));

            var distinctCategories = categorizedEffects
                .Select(v => EffectAllowedValuesShouldNotMixIncompatibleEffects.EffectToCategory[v])
                .Distinct(StringComparer.Ordinal)
                .Count();

            if (!hasManualConflict && distinctCategories <= 1)
            {
                return Array.Empty<LinterOutput>();
            }

            var conflictingEffects = string.Join(
                ", ",
                (hasManualConflict ? manualCombination : categorizedEffects)
                    .OrderBy(v => v, StringComparer.OrdinalIgnoreCase)
                    .ToArray());

            return new[]
            {
                this.CreateError(
                    expression: expression.Effect,
                    parameterName,
                    conflictingEffects)
            };
        }

        /// <summary>
        /// Checks whether an effect is a known control plane effect other than Disabled.
        /// </summary>
        private static bool IsKnownNonDisabledEffect(string effect)
        {
            return EffectAllowedValuesShouldNotMixIncompatibleEffects.EffectToCategory.ContainsKey(key: effect) ||
                string.Equals(a: effect, b: "Audit", comparisonType: StringComparison.OrdinalIgnoreCase) ||
                string.Equals(a: effect, b: "Deny", comparisonType: StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Checks whether the policy uses a control plane mode (All or Indexed) as opposed to a dataplane mode.
        /// </summary>
        private static bool IsControlPlaneMode(ThenExpression expression)
        {
            var definition = EffectAllowedValuesShouldNotMixIncompatibleEffects.FindPolicyDefinition(expression);
            var mode = definition?.Properties?.Mode?.Value?.ToString();

            return mode == null ||
                string.Equals(mode, "All", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(mode, "Indexed", StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Walks up the expression tree to find the enclosing <see cref="PolicyDefinition"/>.
        /// </summary>
        private static PolicyDefinition? FindPolicyDefinition(PolicyExpression expression)
        {
            for (var current = expression.Parent; current != null; current = current.Parent)
            {
                if (current is PolicyDefinition definition)
                {
                    return definition;
                }
            }

            return null;
        }
    }
}
