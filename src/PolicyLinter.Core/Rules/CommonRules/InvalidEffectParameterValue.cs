// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules
{
    using System;
    using System.Linq;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Microsoft.WindowsAzure.ResourceStack.Common.Collections;

    /// <summary>
    /// Flags effect parameter values that are not policy effects.
    /// </summary>
    public sealed class InvalidEffectParameterValue : LinterRule<PolicyDefinitionProperties>
    {
        private const string RuleTitle = "Invalid Effect Parameter Value";

        private const string RuleDescription =
            "The effect parameter '{0}' allows the value '{1}', which is not a policy effect. Correct the value to the intended effect or remove it.";

        private static readonly OrdinalInsensitiveHashSet ControlPlaneEffects = new OrdinalInsensitiveHashSet
        {
            "append",
            "audit",
            "auditAction",
            "auditIfNotExists",
            "deny",
            "denyAction",
            "deployIfNotExists",
            "disabled",
            "manual",
            "modify",
        };

        /// <summary>
        /// Initializes a new instance of the <see cref="InvalidEffectParameterValue"/> class.
        /// </summary>
        public InvalidEffectParameterValue() : base(
            identifier: "invalid-effect-parameter-value",
            category: Category.BestPractices,
            title: InvalidEffectParameterValue.RuleTitle,
            descriptionFormat: InvalidEffectParameterValue.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(PolicyDefinitionProperties expression, LinterContext context)
        {
            // Resource Provider modes have their own effects, which this rule doesn't know.
            var effect = expression.PolicyRule.Then.Effect;
            if (!context.IsControlPlanePolicyMode ||
                !effect.HasSimpleParameterizedValue(context: context, out var parameterName, out var allowedValues, out var defaultValue))
            {
                return Array.Empty<LinterOutput>();
            }

            // The default value must be one of the allowed values, so it's checked only when there are none.
            var values = allowedValues is { Length: > 0 }
                ? allowedValues
                : defaultValue != null ? new[] { defaultValue } : Array.Empty<string>();

            return values
                .Where(value => !InvalidEffectParameterValue.ControlPlaneEffects.Contains(value))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Select(value => this.CreateError(effect, parameterName, value))
                .ToArray();
        }
    }
}
