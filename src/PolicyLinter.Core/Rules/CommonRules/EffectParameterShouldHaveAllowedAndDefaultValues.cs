// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules
{
    using System;
    using System.Collections.Generic;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions;

    /// <summary>
    /// Ensures that the effect parameter has both allowedValues and defaultValue defined.
    /// Both properties are important for built-in policies to constrain the effect values
    /// and provide a sensible default.
    /// </summary>
    public sealed class EffectParameterShouldHaveAllowedAndDefaultValues : LinterRule<ThenExpression>
    {
        private const string RuleTitle = "Effect Parameter Should Have allowedValues and defaultValue";
        private const string RuleDescription = "The effect parameter '{0}' is missing '{1}'. Use allowedValues and defaultValue to constrain the effect to a known set of values and provide a sensible default when the parameter is not explicitly set.";

        /// <summary>
        /// Initializes a new instance of the <see cref="EffectParameterShouldHaveAllowedAndDefaultValues"/> class.
        /// </summary>
        public EffectParameterShouldHaveAllowedAndDefaultValues() : base(
            identifier: "effect-parameter-should-have-allowed-and-default-values",
            category: Category.BestPractices,
            title: EffectParameterShouldHaveAllowedAndDefaultValues.RuleTitle,
            descriptionFormat: EffectParameterShouldHaveAllowedAndDefaultValues.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(ThenExpression expression, LinterContext context)
        {
            if (!expression.Effect.HasSimpleParameterizedValue(context: context, out var parameterName, out var allowedValues, out var defaultValue))
            {
                return Array.Empty<LinterOutput>();
            }

            var warnings = new List<LinterOutput>();

            if (allowedValues == null)
            {
                warnings.Add(this.CreateWarning(
                    expression: expression.Effect,
                    parameterName,
                    "allowedValues"));
            }

            if (defaultValue == null)
            {
                warnings.Add(this.CreateWarning(
                    expression: expression.Effect,
                    parameterName,
                    "defaultValue"));
            }

            return warnings.ToArray();
        }
    }
}
