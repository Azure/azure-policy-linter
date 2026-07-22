// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules
{
    using System;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Extensions;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Microsoft.WindowsAzure.ResourceStack.Common.Collections;
    using Microsoft.WindowsAzure.ResourceStack.Common.Extensions;

    /// <summary>
    /// Detects policies with hard-coded enforcement effects that should be parameterized.
    /// </summary>
    public sealed class HardCodedPolicyEnforcementEffect : LinterRule<ThenExpression>
    {
        private const string RuleTitle = "Hard-Coded Policy Enforcement Effect";
        private const string RuleDescription = "The policy effect '{0}' is hard-coded, so assignments cannot select a non-enforcement effect. Add a string 'effect' parameter with defaultValue '{1}' and allowedValues containing '{2}', then set the policy effect to \"[parameters('effect')]\".";

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
        /// Initializes a new instance of the <see cref="HardCodedPolicyEnforcementEffect"/> class.
        /// </summary>
        public HardCodedPolicyEnforcementEffect() : base(
            identifier: "hard-coded-policy-enforcement-effect",
            category: Category.BestPractices,
            title: HardCodedPolicyEnforcementEffect.RuleTitle,
            descriptionFormat: HardCodedPolicyEnforcementEffect.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(ThenExpression expression, LinterContext context)
        {
            var effectValue = expression.Effect.HasLiteralValue ? expression.Effect.Value.ToStringValue() : null;
            if (effectValue != null && HardCodedPolicyEnforcementEffect.EnforcementEffects.Contains(effectValue))
            {
                var auditCounterpart = effectValue.EqualsOrdinalInsensitively("deployIfNotExists") ? "auditIfNotExists"
                    : effectValue.EqualsOrdinalInsensitively("denyAction") ? "auditAction"
                    : "audit";
                var suggestedParameterValues = new[]
                {
                    auditCounterpart,
                    effectValue,
                    "disabled"
                };

                return new[]
                {
                    this.CreateWarning(
                        expression: expression.Effect,
                        effectValue,
                        auditCounterpart,
                        string.Join("', '", suggestedParameterValues)),
                };
            }

            return Array.Empty<LinterOutput>();
        }
    }
}
