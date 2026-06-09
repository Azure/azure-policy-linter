// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.WindowsAzure.Governance.PolicyLinter.Core.Rules.CommonRules
{
    using Microsoft.WindowsAzure.Governance.PolicyLinter.Core.Rules.Contracts;
    using System;
    using Microsoft.WindowsAzure.Governance.PolicyLinter.Core.Expressions;
    using Microsoft.WindowsAzure.Governance.PolicyLinter.Core.Extensions;
    using Microsoft.WindowsAzure.ResourceStack.Common.Collections;
    using Microsoft.WindowsAzure.ResourceStack.Common.Extensions;

    /// <summary>
    /// Detects policies with hard-coded enforcement effects that should be parameterized.
    /// </summary>
    public sealed class HardCodedEnforcementPolicyEffect : LinterRule<ThenExpression>
    {
        private const string RuleTitle = "Hard-Coded Enforcement Policy Effect";
        private const string RuleDescription = "The policy definition has a hard-coded enforcement effect: '{0}'. Consider adding an \"effect\" policy definition parameter with default value: '{1}' and allowed values: '{2}' and replace the hard-coded effect with \"[parameters('effect')]\". Parameterizing the policy effect makes it easy reuse the policy as well as to follow safe deployment practices (start with audit, then enforce).";

        /// <summary>
        /// The set of enforcement effects.
        /// </summary>
        private static readonly OrdinalInsensitiveHashSet EnforcementEffects = new OrdinalInsensitiveHashSet()
        {
            "deployIfNotExists",
            "append",
            "modify",
            "deny"
        };

        /// <summary>
        /// Initializes a new instance of the <see cref="HardCodedEnforcementPolicyEffect"/> class.
        /// </summary>
        public HardCodedEnforcementPolicyEffect() : base(
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
            if (expression.Effect.HasLiteralValue && EnforcementEffects.Contains(expression.Effect.Value.ToStringValue()))
            {
                var effectValue = expression.Effect.Value.ToStringValue();
                var auditCounterpart = effectValue.EqualsOrdinalInsensitively("deployIfNotExists") ? "auditIfNotExists" : "audit";
                var suggestedParameterValues = new[]
                {
                    auditCounterpart,
                    effectValue,
                    "disabled"
                };

                return new[] { this.CreateInformational(expression.Effect, expression.Effect.Value.ToStringValue()!, auditCounterpart, string.Join(',', suggestedParameterValues)) };
            }

            return Array.Empty<LinterOutput>();

        }
    }
}
