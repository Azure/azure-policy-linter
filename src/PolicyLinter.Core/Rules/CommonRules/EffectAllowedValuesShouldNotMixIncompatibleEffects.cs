// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.WindowsAzure.Governance.PolicyLinter.Core.Rules.CommonRules
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using Microsoft.WindowsAzure.Governance.PolicyLinter.Core.Rules.Contracts;
    using Microsoft.WindowsAzure.Governance.PolicyLinter.Core.Expressions;

    /// <summary>
    /// Ensures that the effect parameter's allowedValues do not mix effects from
    /// incompatible effects. Effects that require different 'details' block configurations
    /// (e.g. Modify details vs. IfNotExists details vs. Action details) cannot coexist
    /// in the same allowedValues because only one details shape can be specified.
    /// Effects that do not require a details block (e.g. Audit, Deny, Disabled) are
    /// compatible with any other effect and are not flagged.
    /// </summary>
    public sealed class EffectAllowedValuesShouldNotMixIncompatibleEffects : LinterRule<ThenExpression>
    {
        private const string RuleTitle = "Effect Allowed Values Should Not Mix Incompatible Effects";
        private const string RuleDescription = "The effect parameter '{0}': {1}";

        private const string ModifyDetailsCategory = "ModifyDetails";
        private const string IfNotExistsDetailsCategory = "IfNotExistsDetails";
        private const string ActionDetailsCategory = "ActionDetails";
        private const string AppendDetailsCategory = "AppendDetails";

        private static readonly Dictionary<string, string> EffectToCategory = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { "Modify", EffectAllowedValuesShouldNotMixIncompatibleEffects.ModifyDetailsCategory },
            { "AuditIfNotExists", EffectAllowedValuesShouldNotMixIncompatibleEffects.IfNotExistsDetailsCategory },
            { "DeployIfNotExists", EffectAllowedValuesShouldNotMixIncompatibleEffects.IfNotExistsDetailsCategory },
            { "DenyAction", EffectAllowedValuesShouldNotMixIncompatibleEffects.ActionDetailsCategory },
            { "AuditAction", EffectAllowedValuesShouldNotMixIncompatibleEffects.ActionDetailsCategory },
            { "Append", EffectAllowedValuesShouldNotMixIncompatibleEffects.AppendDetailsCategory },
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

            var categorizedValues = allowedValues
                .Where(v => EffectAllowedValuesShouldNotMixIncompatibleEffects.EffectToCategory.ContainsKey(v))
                .GroupBy(v => EffectAllowedValuesShouldNotMixIncompatibleEffects.EffectToCategory[v], StringComparer.Ordinal)
                .ToDictionary(g => g.Key, g => g.ToArray());

            if (categorizedValues.Count <= 1)
            {
                return Array.Empty<LinterOutput>();
            }

            var conflictDescription = string.Join(
                ", ",
                categorizedValues
                    .OrderBy(kvp => kvp.Key, StringComparer.Ordinal)
                    .Select(kvp => $"{kvp.Key} ({string.Join(", ", kvp.Value)})")
                    .ToArray());

            return new[]
            {
                this.CreateError(
                    expression: expression.Effect,
                    parameterName,
                    $"allowedValues mixes effects from incompatible effects: {conflictDescription}. Effects in each category require a different 'details' block configuration and cannot coexist in the same allowedValues.")
            };
        }

        /// <summary>
        /// Checks whether the policy uses a control plane mode (All or Indexed) as opposed to a dataplane mode.
        /// </summary>
        private static bool IsControlPlaneMode(ThenExpression expression)
        {
            var definition = expression.Parent?.Parent as PolicyDefinition;
            var mode = definition?.Properties?.Mode?.Value?.ToString();

            return mode == null ||
                string.Equals(mode, "All", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(mode, "Indexed", StringComparison.OrdinalIgnoreCase);
        }
    }
}
