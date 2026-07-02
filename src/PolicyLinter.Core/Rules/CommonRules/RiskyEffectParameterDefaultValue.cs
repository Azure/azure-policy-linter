// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules
{
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using System;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions;
    using Microsoft.WindowsAzure.ResourceStack.Common.Collections;
    using Microsoft.WindowsAzure.ResourceStack.Common.Extensions;

    /// <summary>
    /// Detects parameterized policy effects whose default value is a risky enforcement effect.
    /// </summary>
    public sealed class RiskyEffectParameterDefaultValue : LinterRule<ThenExpression>
    {
        private const string RuleTitle = "Risky Effect Parameter Default Value";
        private const string RuleDescription = "The policy effect is parameterized, but the default value of the reference parameter: '{0}' is: '{1}'. This increases the risk of accidentally assigning the policy with an enforcement effect. Consider setting the parameter default value to: '{2}' and: '{3}' as the parameter allowed values.";

        /// <summary>
        /// The risky default effect parameter values.
        /// </summary>
        private static readonly OrdinalInsensitiveHashSet RiskyDefaultEffectParameters = new OrdinalInsensitiveHashSet()
        {
            "deployIfNotExists",
            "append",
            "modify",
            "deny"
        };

        /// <summary>
        /// Initializes a new instance of the <see cref="RiskyEffectParameterDefaultValue"/> class.
        /// </summary>
        public RiskyEffectParameterDefaultValue() : base(
            identifier: "risky-effect-parameter-default-value",
            category: Category.BestPractices,
            title: RuleTitle,
            descriptionFormat: RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(ThenExpression expression, LinterContext context)
        {
            if (expression.Effect.HasSimpleParameterizedValue(context: context, out var parameterName, out var _, out var defaultValue) &&
                defaultValue != null &&
                RiskyDefaultEffectParameters.Contains(defaultValue))
            {
                var auditCounterpart = defaultValue.EqualsOrdinalInsensitively("deployIfNotExists") ? "auditIfNotExists" : "audit";
                var suggestedParameterValues = new[]
                {
                    auditCounterpart,
                    defaultValue,
                    "disabled"
                };

                return new[] { this.CreateWarning(expression.Effect, parameterName, defaultValue, auditCounterpart, string.Join(',', suggestedParameterValues)) };
            }

            return Array.Empty<LinterOutput>();
        }
    }
}
