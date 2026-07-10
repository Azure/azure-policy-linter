// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules
{
    using System;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions;

    /// <summary>
    /// Detects a parameterized policy effect whose parameter does not constrain the effect
    /// with an allowedValues array. An absent or empty allowedValues lets the parameter accept
    /// any value at assignment time.
    /// </summary>
    public sealed class EffectParameterMissingAllowedValues : LinterRule<ThenExpression>
    {
        private const string RuleTitle = "Effect Parameter Missing Allowed Values";
        private const string RuleDescription = "The effect parameter '{0}' does not constrain its allowedValues, so any value can be assigned. Add an allowedValues array to restrict the effect to a known set of values (e.g. ['Audit', 'Deny', 'Disabled']).";

        /// <summary>
        /// Initializes a new instance of the <see cref="EffectParameterMissingAllowedValues"/> class.
        /// </summary>
        public EffectParameterMissingAllowedValues() : base(
            identifier: "effect-parameter-missing-allowed-values",
            category: Category.BestPractices,
            title: EffectParameterMissingAllowedValues.RuleTitle,
            descriptionFormat: EffectParameterMissingAllowedValues.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(ThenExpression expression, LinterContext context)
        {
            if (!expression.Effect.HasSimpleParameterizedValue(context: context, out var parameterName, out var allowedValues, out _))
            {
                return Array.Empty<LinterOutput>();
            }

            if (allowedValues != null && allowedValues.Length > 0)
            {
                return Array.Empty<LinterOutput>();
            }

            return new[] { this.CreateWarning(expression: expression.Effect, parameterName) };
        }
    }
}
