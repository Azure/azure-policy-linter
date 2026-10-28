// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules
{
    using System;
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

            if (expression.Then.CanHaveEffect(context: context, effects: NsgSecurityRuleChildOnlyEnforcement.EnforcementEffects) &&
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
    }
}
