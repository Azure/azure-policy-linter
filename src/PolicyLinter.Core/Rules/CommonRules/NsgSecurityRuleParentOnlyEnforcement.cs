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
    using Microsoft.WindowsAzure.ResourceStack.Common.Extensions;

    /// <summary>
    /// Flags enforcement policies on the security rules of a parent NSG that don't also target the security rule resource type.
    /// </summary>
    public sealed class NsgSecurityRuleParentOnlyEnforcement : LinterRule<PolicyRule>
    {
        private const string RuleTitle = "NSG Security Rule Parent-Only Enforcement";

        private const string RuleDescription =
            "The policy enforces on security rules through 'Microsoft.Network/networkSecurityGroups/securityRules[*]' fields but not on the 'Microsoft.Network/networkSecurityGroups/securityRules' resource type. Security rules created or changed directly are not evaluated by this policy. Also enforce on the security rule resource type.";

        private const string NsgType = "Microsoft.Network/networkSecurityGroups";

        private const string SecurityRuleType = "Microsoft.Network/networkSecurityGroups/securityRules";

        private const string SecurityRulesArrayAlias = "Microsoft.Network/networkSecurityGroups/securityRules[*]";

        private static readonly OrdinalInsensitiveHashSet EnforcementEffects = new OrdinalInsensitiveHashSet
        {
            "append",
            "deny",
            "modify",
        };

        /// <summary>
        /// Initializes a new instance of the <see cref="NsgSecurityRuleParentOnlyEnforcement"/> class.
        /// </summary>
        public NsgSecurityRuleParentOnlyEnforcement() : base(
            identifier: "nsg-security-rule-parent-only-enforcement",
            category: Category.BestPractices,
            title: NsgSecurityRuleParentOnlyEnforcement.RuleTitle,
            descriptionFormat: NsgSecurityRuleParentOnlyEnforcement.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(PolicyRule expression, LinterContext context)
        {
            var resourceTypes = expression.If.ReferencedResourceTypes;

            if (NsgSecurityRuleParentOnlyEnforcement.CanEnforce(effect: expression.Then.Effect, context: context) &&
                resourceTypes.Contains(NsgSecurityRuleParentOnlyEnforcement.NsgType) &&
                !resourceTypes.Contains(NsgSecurityRuleParentOnlyEnforcement.SecurityRuleType) &&
                NsgSecurityRuleParentOnlyEnforcement.ReferencesSecurityRulesArray(ifCondition: expression.If))
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
                return NsgSecurityRuleParentOnlyEnforcement.EnforcementEffects.Contains(effect.Value.ToString());
            }

            return effect.HasSimpleParameterizedValue(context: context, out _, out var allowedValues, out _) &&
                allowedValues != null &&
                allowedValues.Any(value => NsgSecurityRuleParentOnlyEnforcement.EnforcementEffects.Contains(value));
        }

        /// <summary>
        /// Determines whether the condition references a field of the parent NSG's security rules array.
        /// </summary>
        private static bool ReferencesSecurityRulesArray(IfCondition ifCondition)
        {
            var found = false;
            ifCondition.Visit(new PolicyExpressionVisitor
            {
                Visit = node =>
                {
                    if (node is Reference reference &&
                        reference.IsResolvedFieldReference() &&
                        reference.Identifier.StartsWithOrdinalInsensitively(NsgSecurityRuleParentOnlyEnforcement.SecurityRulesArrayAlias))
                    {
                        found = true;
                    }
                },
            });

            return found;
        }
    }
}
