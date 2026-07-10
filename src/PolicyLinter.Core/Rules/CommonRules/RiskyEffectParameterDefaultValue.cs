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
        private const string RuleDescription = "The policy effect is parameterized, but the referenced parameter '{0}' defaults to an enforcement effect '{1}'. This increases the risk of accidentally assigning the policy with an enforcement effect. Consider setting the parameter default value to '{2}'.";

        /// <summary>
        /// The set of enforcement effects.
        /// </summary>
        private static readonly OrdinalInsensitiveHashSet EnforcementEffects = new OrdinalInsensitiveHashSet()
        {
            "deployIfNotExists",
            "append",
            "modify",
            "deny",
            "denyAction"
        };

        /// <summary>
        /// Initializes a new instance of the <see cref="RiskyEffectParameterDefaultValue"/> class.
        /// </summary>
        public RiskyEffectParameterDefaultValue() : base(
            identifier: "risky-effect-parameter-default-value",
            category: Category.BestPractices,
            title: RiskyEffectParameterDefaultValue.RuleTitle,
            descriptionFormat: RiskyEffectParameterDefaultValue.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(ThenExpression expression, LinterContext context)
        {
            if (!expression.Effect.HasSimpleParameterizedValue(context: context, out var parameterName, out var _, out var defaultValue))
            {
                return Array.Empty<LinterOutput>();
            }

            if (defaultValue == null || !RiskyEffectParameterDefaultValue.EnforcementEffects.Contains(defaultValue))
            {
                return Array.Empty<LinterOutput>();
            }

            var safeDefault =
                defaultValue.EqualsOrdinalInsensitively("deployIfNotExists") ? "auditIfNotExists" :
                defaultValue.EqualsOrdinalInsensitively("denyAction") ? "auditAction" :
                "audit";

            return new[] { this.CreateWarning(expression.Effect, parameterName, defaultValue, safeDefault) };
        }
    }
}
