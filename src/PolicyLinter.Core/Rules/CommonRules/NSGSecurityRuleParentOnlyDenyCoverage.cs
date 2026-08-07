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
    using Newtonsoft.Json.Linq;

    /// <summary>
    /// Detects deny-capable policies that reference security rules through the parent network
    /// security group without also referencing the security rule child resource.
    /// </summary>
    public sealed class NSGSecurityRuleParentOnlyDenyCoverage : LinterRule<PolicyDefinitionProperties>
    {
        private const string SecurityRulesAlias = "Microsoft.Network/networkSecurityGroups/securityRules";
        private const string RuleTitle = "NSG Security Rule Parent-Only Deny Coverage";
        private const string RuleDescription =
            "The alias '{0}' applies to security rules submitted with the parent network security group. " +
            "Requests that directly create or update 'securityRules' child resources are not covered. " +
            "Add equivalent child resource coverage in this or another policy.";

        /// <summary>
        /// Initializes a new instance of the <see cref="NSGSecurityRuleParentOnlyDenyCoverage"/> class.
        /// </summary>
        public NSGSecurityRuleParentOnlyDenyCoverage() : base(
            identifier: "nsg-security-rule-parent-only-deny-coverage",
            category: Category.BestPractices,
            title: NSGSecurityRuleParentOnlyDenyCoverage.RuleTitle,
            descriptionFormat: NSGSecurityRuleParentOnlyDenyCoverage.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(PolicyDefinitionProperties expression, LinterContext context)
        {
            if (!NSGSecurityRuleParentOnlyDenyCoverage.IsDenyCapable(
                effect: expression.PolicyRule.Then.Effect,
                context: context))
            {
                return Array.Empty<LinterOutput>();
            }

            Reference? parentAlias = null;
            var referencesChildAlias = false;

            // The targeted resource types are inferred from the security rule aliases the condition
            // uses. TODO: replace this with the linter's resource applicability analysis when it is
            // available, so that the targeted resource types are derived from the whole policy rule.
            expression.PolicyRule.If.Visit(new PolicyExpressionVisitor
            {
                Visit = policyExpression =>
                {
                    if (policyExpression is not Reference reference ||
                        !reference.IsResolvedFieldReference())
                    {
                        return;
                    }

                    if (NSGSecurityRuleParentOnlyDenyCoverage.IsChildAlias(identifier: reference.Identifier))
                    {
                        referencesChildAlias = true;
                    }
                    else if (parentAlias == null &&
                        NSGSecurityRuleParentOnlyDenyCoverage.IsParentAlias(identifier: reference.Identifier))
                    {
                        parentAlias = reference;
                    }
                },
            });

            if (parentAlias == null || referencesChildAlias)
            {
                return Array.Empty<LinterOutput>();
            }

            return new[]
            {
                this.CreateWarning(parentAlias, parentAlias.Identifier),
            };
        }

        /// <summary>
        /// Determines whether the alias selects security rules through the parent network security
        /// group, either as the whole 'securityRules' collection or through a 'securityRules[*]' member.
        /// </summary>
        private static bool IsParentAlias(string identifier)
        {
            if (!identifier.StartsWith(
                NSGSecurityRuleParentOnlyDenyCoverage.SecurityRulesAlias,
                StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            return identifier.Length == NSGSecurityRuleParentOnlyDenyCoverage.SecurityRulesAlias.Length ||
                identifier[NSGSecurityRuleParentOnlyDenyCoverage.SecurityRulesAlias.Length] == '[';
        }

        /// <summary>
        /// Determines whether the alias selects a property of the security rule child resource.
        /// </summary>
        private static bool IsChildAlias(string identifier)
        {
            return identifier.StartsWith(
                    NSGSecurityRuleParentOnlyDenyCoverage.SecurityRulesAlias,
                    StringComparison.OrdinalIgnoreCase) &&
                identifier.Length > NSGSecurityRuleParentOnlyDenyCoverage.SecurityRulesAlias.Length &&
                identifier[NSGSecurityRuleParentOnlyDenyCoverage.SecurityRulesAlias.Length] == '/';
        }

        private static bool IsDenyCapable(Property effect, LinterContext context)
        {
            if (effect.HasLiteralValue)
            {
                return effect.Value.Type == JTokenType.String &&
                    string.Equals(effect.Value.Value<string>(), "deny", StringComparison.OrdinalIgnoreCase);
            }

            return effect.HasSimpleParameterizedValue(
                    context: context,
                    out _,
                    out var allowedValues,
                    out _) &&
                (allowedValues == null ||
                allowedValues.Any(value => string.Equals(value, "deny", StringComparison.OrdinalIgnoreCase)));
        }
    }
}
