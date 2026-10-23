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
    /// Flags enforcement policies on NSG security rules that don't also target the parent NSG.
    /// </summary>
    public sealed class NsgSecurityRuleChildOnlyEnforcement : LinterRule<PolicyRule>
    {
        private const string RuleTitle = "NSG Security Rule Child-Only Enforcement";

        private const string RuleDescription =
            "The policy enforces on the 'Microsoft.Network/networkSecurityGroups/securityRules' resource type but not on 'Microsoft.Network/networkSecurityGroups'. Security rules created or changed through the parent network security group are not evaluated by this policy. Also enforce on the parent network security group.";

        private const string NsgType = "Microsoft.Network/networkSecurityGroups";

        private const string SecurityRuleType = "Microsoft.Network/networkSecurityGroups/securityRules";

        private static readonly OrdinalInsensitiveHashSet EnforcementEffects = new OrdinalInsensitiveHashSet
        {
            "append",
            "deny",
            "modify",
        };

        /// <summary>
        /// Initializes a new instance of the <see cref="NsgSecurityRuleChildOnlyEnforcement"/> class.
        /// </summary>
        public NsgSecurityRuleChildOnlyEnforcement() : base(
            identifier: "nsg-security-rule-child-only-enforcement",
            category: Category.BestPractices,
            title: NsgSecurityRuleChildOnlyEnforcement.RuleTitle,
            descriptionFormat: NsgSecurityRuleChildOnlyEnforcement.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(PolicyRule expression, LinterContext context)
        {
            var resourceTypes = expression.If.ReferencedResourceTypes;

            if (NsgSecurityRuleChildOnlyEnforcement.CanEnforce(effect: expression.Then.Effect, context: context) &&
                resourceTypes.Contains(NsgSecurityRuleChildOnlyEnforcement.SecurityRuleType) &&
                !resourceTypes.Contains(NsgSecurityRuleChildOnlyEnforcement.NsgType))
            {
                return new[]
                {
                    this.CreateWarning(expression.If),
                };
            }

            return Array.Empty<LinterOutput>();
        }

        /// <summary>
        /// Determines whether the effect is an enforcement effect, or a parameter whose allowedValues include one.
        /// </summary>
        private static bool CanEnforce(Property effect, LinterContext context)
        {
            if (effect.HasLiteralValue)
            {
                return NsgSecurityRuleChildOnlyEnforcement.EnforcementEffects.Contains(effect.Value.ToString());
            }

            return effect.HasSimpleParameterizedValue(context: context, out _, out var allowedValues, out _) &&
                allowedValues != null &&
                allowedValues.Any(value => NsgSecurityRuleChildOnlyEnforcement.EnforcementEffects.Contains(value));
        }
    }
}
