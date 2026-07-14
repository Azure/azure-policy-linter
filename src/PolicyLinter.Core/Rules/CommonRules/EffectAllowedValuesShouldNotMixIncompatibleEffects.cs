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
    /// Ensures that the effect parameter's allowedValues do not mix effects that require
    /// incompatible 'details' blocks. A parameterized effect shares one static 'then.details'
    /// block, so effects whose 'details' have different shapes (for example Modify vs.
    /// DeployIfNotExists vs. Manual) cannot coexist in the same allowedValues. Effects that
    /// need no 'details' block (Audit, Deny, Disabled) are compatible with any effect and are
    /// not flagged.
    /// </summary>
    public sealed class EffectAllowedValuesShouldNotMixIncompatibleEffects : LinterRule<ThenExpression>
    {
        private const string RuleTitle = "Effect Allowed Values Should Not Mix Incompatible Effects";
        private const string RuleDescription =
            "The effect parameter '{0}' has allowedValues that mix effects requiring incompatible 'details' blocks: {1}. A parameterized effect shares one static 'then.details' block, so allowedValues must not combine effects that need different 'details' shapes.";

        private const string ModifyDetailsCategory = "ModifyDetails";
        private const string IfNotExistsDetailsCategory = "IfNotExistsDetails";
        private const string ActionDetailsCategory = "ActionDetails";
        private const string AppendDetailsCategory = "AppendDetails";
        private const string ManualDetailsCategory = "ManualDetails";

        // Maps each effect to the shape of 'details' it requires. Effects sharing a category
        // are interchangeable; effects in different categories are not. 'mutate' and
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
            // Skip dataplane policies -- they may use effects not in our known set.
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

            var distinctCategories = categorizedEffects
                .Select(v => EffectAllowedValuesShouldNotMixIncompatibleEffects.EffectToCategory[v])
                .Distinct(StringComparer.Ordinal)
                .Count();

            if (distinctCategories <= 1)
            {
                return Array.Empty<LinterOutput>();
            }

            var conflictingEffects = string.Join(
                ", ",
                categorizedEffects.OrderBy(v => v, StringComparer.OrdinalIgnoreCase).ToArray());

            return new[]
            {
                this.CreateError(
                    expression: expression.Effect,
                    parameterName,
                    conflictingEffects)
            };
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
