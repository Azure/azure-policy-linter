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
    /// Detects a parameterized policy effect whose parameter does not define a defaultValue.
    /// Without a default, the effect must be supplied at every assignment and the policy has no
    /// predictable behavior when it is omitted.
    /// </summary>
    public sealed class EffectParameterMissingDefaultValue : LinterRule<ThenExpression>
    {
        private const string RuleTitle = "Effect Parameter Missing Default Value";
        private const string RuleDescription = "The effect parameter '{0}' does not define a defaultValue, so the effect must be set on every assignment. Add a defaultValue so the policy behaves predictably when the parameter is not set.";

        /// <summary>
        /// Initializes a new instance of the <see cref="EffectParameterMissingDefaultValue"/> class.
        /// </summary>
        public EffectParameterMissingDefaultValue() : base(
            identifier: "effect-parameter-missing-default-value",
            category: Category.BestPractices,
            title: EffectParameterMissingDefaultValue.RuleTitle,
            descriptionFormat: EffectParameterMissingDefaultValue.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(ThenExpression expression, LinterContext context)
        {
            if (!expression.Effect.HasSimpleParameterizedValue(context: context, out var parameterName, out _, out var defaultValue))
            {
                return Array.Empty<LinterOutput>();
            }

            if (defaultValue != null)
            {
                return Array.Empty<LinterOutput>();
            }

            return new[] { this.CreateWarning(expression: expression.Effect, parameterName) };
        }
    }
}
