// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules
{
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using System;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Extensions;
    using Microsoft.WindowsAzure.ResourceStack.Common.Collections;
    using Microsoft.WindowsAzure.ResourceStack.Common.Extensions;

    /// <summary>
    /// Detects policies with hard-coded enforcement effects that should be parameterized.
    /// </summary>
    public sealed class HardCodedPolicyEnforcementEffect : LinterRule<ThenExpression>
    {
        private const string RuleTitle = "Hard-Coded Policy Enforcement Effect";
        private const string RuleDescription = "The policy definition has a hard-coded enforcement effect: '{0}'. Consider adding an \"effect\" policy definition parameter with default value: '{1}' and allowed values: '{2}' and replace the hard-coded effect with \"[parameters('effect')]\".";

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
            title: RuleTitle,
            descriptionFormat: RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(ThenExpression expression, LinterContext context)
        {
            var effectValue = expression.Effect.HasLiteralValue ? expression.Effect.Value.ToStringValue() : null;
            if (effectValue != null && EnforcementEffects.Contains(effectValue))
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

                return new[] { this.CreateWarning(expression.Effect, effectValue, auditCounterpart, string.Join(',', suggestedParameterValues)) };
            }

            return Array.Empty<LinterOutput>();
        }
    }
}
