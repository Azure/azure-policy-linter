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
    /// Detects deny-capable policies that reference the security rule child resource without also
    /// referencing security rules through the parent network security group.
    /// </summary>
    public sealed class NSGSecurityRuleChildOnlyDenyCoverage : LinterRule<PolicyDefinitionProperties>
    {
        private const string SecurityRulesAlias = "Microsoft.Network/networkSecurityGroups/securityRules";
        private const string RuleTitle = "NSG Security Rule Child-Only Deny Coverage";
        private const string RuleDescription =
            "The alias '{0}' targets security rules deployed as their own resource, but the policy does not target the security rules carried on the parent network security group. A security rule can be created either way. Cover both routes, here or in another policy.";

        /// <summary>
        /// Initializes a new instance of the <see cref="NSGSecurityRuleChildOnlyDenyCoverage"/> class.
        /// </summary>
        public NSGSecurityRuleChildOnlyDenyCoverage() : base(
            identifier: "nsg-security-rule-child-only-deny-coverage",
            category: Category.BestPractices,
            title: NSGSecurityRuleChildOnlyDenyCoverage.RuleTitle,
            descriptionFormat: NSGSecurityRuleChildOnlyDenyCoverage.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(PolicyDefinitionProperties expression, LinterContext context)
        {
            // Indexed mode and an absent mode do not evaluate the security rule child resource.
            if (!NSGSecurityRuleChildOnlyDenyCoverage.IsAllMode(mode: expression.Mode) ||
                !NSGSecurityRuleChildOnlyDenyCoverage.IsDenyCapable(
                    effect: expression.PolicyRule.Then.Effect,
                    context: context))
            {
                return Array.Empty<LinterOutput>();
            }

            Reference? childAlias = null;
            var referencesParentAlias = false;

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

                    if (NSGSecurityRuleChildOnlyDenyCoverage.IsParentAlias(identifier: reference.Identifier))
                    {
                        referencesParentAlias = true;
                    }
                    else if (childAlias == null &&
                        NSGSecurityRuleChildOnlyDenyCoverage.IsChildAlias(identifier: reference.Identifier))
                    {
                        childAlias = reference;
                    }
                },
            });

            if (childAlias == null || referencesParentAlias)
            {
                return Array.Empty<LinterOutput>();
            }

            return new[]
            {
                this.CreateWarning(childAlias, childAlias.Identifier),
            };
        }

        /// <summary>
        /// Determines whether the alias selects security rules through the parent network security
        /// group, either as the whole 'securityRules' collection or through a 'securityRules[*]' member.
        /// </summary>
        private static bool IsParentAlias(string identifier)
        {
            if (!identifier.StartsWith(
                NSGSecurityRuleChildOnlyDenyCoverage.SecurityRulesAlias,
                StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            return identifier.Length == NSGSecurityRuleChildOnlyDenyCoverage.SecurityRulesAlias.Length ||
                identifier[NSGSecurityRuleChildOnlyDenyCoverage.SecurityRulesAlias.Length] == '[';
        }

        /// <summary>
        /// Determines whether the alias selects a property of the security rule child resource.
        /// </summary>
        private static bool IsChildAlias(string identifier)
        {
            return identifier.StartsWith(
                    NSGSecurityRuleChildOnlyDenyCoverage.SecurityRulesAlias,
                    StringComparison.OrdinalIgnoreCase) &&
                identifier.Length > NSGSecurityRuleChildOnlyDenyCoverage.SecurityRulesAlias.Length &&
                identifier[NSGSecurityRuleChildOnlyDenyCoverage.SecurityRulesAlias.Length] == '/';
        }

        private static bool IsAllMode(Property? mode)
        {
            return mode?.HasLiteralValue == true &&
                mode.Value.Type == JTokenType.String &&
                string.Equals(mode.Value.Value<string>(), "all", StringComparison.OrdinalIgnoreCase);
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
