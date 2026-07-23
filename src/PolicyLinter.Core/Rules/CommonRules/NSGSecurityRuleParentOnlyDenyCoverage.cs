// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Newtonsoft.Json.Linq;

    /// <summary>
    /// Detects deny-capable policies that cover security rules submitted in the parent
    /// network security group resource without selecting child security-rule resources.
    /// </summary>
    public sealed class NSGSecurityRuleParentOnlyDenyCoverage : LinterRule<PolicyDefinitionProperties>
    {
        private const string RuleTitle = "NSG Security Rule Parent-Only Deny Coverage";
        private const string RuleDescription =
            "This deny-capable definition covers security rules submitted in the parent NSG collection but not independently deployed child security-rule requests. Add equivalent child coverage in this or another policy.";

        private const string ParentResourceType = "Microsoft.Network/networkSecurityGroups";
        private const string ChildResourceType = "Microsoft.Network/networkSecurityGroups/securityRules";
        private const string ParentSecurityRulesAliasPrefix = "Microsoft.Network/networkSecurityGroups/securityRules[*]";

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

            var selectedResourceTypes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var referencesParentSecurityRulesAlias = false;
            var visitor = new PolicyExpressionVisitor
            {
                Visit = policyExpression =>
                {
                    if (policyExpression is LeafCondition leaf)
                    {
                        NSGSecurityRuleParentOnlyDenyCoverage.AddSelectedResourceTypes(
                            leaf: leaf,
                            selectedResourceTypes: selectedResourceTypes);
                    }
                    else if (policyExpression is Reference reference &&
                        reference.IsResolvedFieldReference() &&
                        NSGSecurityRuleParentOnlyDenyCoverage.IsParentSecurityRulesAlias(identifier: reference.Identifier))
                    {
                        referencesParentSecurityRulesAlias = true;
                    }
                },
            };

            expression.PolicyRule.If.Visit(visitor);

            if (!selectedResourceTypes.Contains(NSGSecurityRuleParentOnlyDenyCoverage.ParentResourceType) ||
                !referencesParentSecurityRulesAlias ||
                (NSGSecurityRuleParentOnlyDenyCoverage.IsAllMode(expression.Mode) &&
                NSGSecurityRuleParentOnlyDenyCoverage.HasEffectiveChildCoverage(expression.PolicyRule.If.Condition)))
            {
                return Array.Empty<LinterOutput>();
            }

            return new[]
            {
                this.CreateWarning(expression: expression.PolicyRule.Then.Effect),
            };
        }

        private static bool IsDenyCapable(Property effect, LinterContext context)
        {
            if (effect.HasLiteralValue)
            {
                return effect.Value.Type == JTokenType.String &&
                    string.Equals(
                        effect.Value.Value<string>(),
                        "deny",
                        StringComparison.OrdinalIgnoreCase);
            }

            return effect.HasSimpleParameterizedValue(
                    context: context,
                    out _,
                    out var allowedValues,
                    out _) &&
                (allowedValues == null ||
                allowedValues.Any(value => string.Equals(value, "deny", StringComparison.OrdinalIgnoreCase)));
        }

        private static bool IsAllMode(Property? mode)
        {
            return mode?.HasLiteralValue == true &&
                mode.Value.Type == JTokenType.String &&
                string.Equals(mode.Value.Value<string>(), "all", StringComparison.OrdinalIgnoreCase);
        }

        private static bool HasEffectiveChildCoverage(Condition condition)
        {
            if (condition is LeafCondition leaf)
            {
                var selectedResourceTypes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                NSGSecurityRuleParentOnlyDenyCoverage.AddSelectedResourceTypes(
                    leaf: leaf,
                    selectedResourceTypes: selectedResourceTypes);
                return selectedResourceTypes.Contains(NSGSecurityRuleParentOnlyDenyCoverage.ChildResourceType);
            }

            if (condition is not Quantifier quantifier || quantifier.Not != null)
            {
                return false;
            }

            if (quantifier.AnyOf != null)
            {
                return quantifier.AnyOf.Value.Any(
                    NSGSecurityRuleParentOnlyDenyCoverage.HasEffectiveChildCoverage);
            }

            if (quantifier.AllOf == null ||
                NSGSecurityRuleParentOnlyDenyCoverage.ContainsParentSecurityRulesAlias(condition))
            {
                return false;
            }

            return quantifier.AllOf.Value.Any(
                NSGSecurityRuleParentOnlyDenyCoverage.ContainsPositiveChildTypeSelection);
        }

        private static bool ContainsPositiveChildTypeSelection(Condition condition)
        {
            var selectedResourceTypes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var visitor = new PolicyExpressionVisitor
            {
                Visit = policyExpression =>
                {
                    if (policyExpression is LeafCondition leaf)
                    {
                        NSGSecurityRuleParentOnlyDenyCoverage.AddSelectedResourceTypes(
                            leaf: leaf,
                            selectedResourceTypes: selectedResourceTypes);
                    }
                },
            };

            condition.Visit(visitor);
            return selectedResourceTypes.Contains(NSGSecurityRuleParentOnlyDenyCoverage.ChildResourceType);
        }

        private static bool ContainsParentSecurityRulesAlias(Condition condition)
        {
            var containsAlias = false;
            var visitor = new PolicyExpressionVisitor
            {
                Visit = policyExpression =>
                {
                    if (policyExpression is Reference reference &&
                        reference.IsResolvedFieldReference() &&
                        NSGSecurityRuleParentOnlyDenyCoverage.IsParentSecurityRulesAlias(reference.Identifier))
                    {
                        containsAlias = true;
                    }
                },
            };

            condition.Visit(visitor);
            return containsAlias;
        }

        private static void AddSelectedResourceTypes(
            LeafCondition leaf,
            HashSet<string> selectedResourceTypes)
        {
            if (leaf.Field?.FieldAccessorReference == null ||
                leaf.Operator == null ||
                !leaf.Operator.HasLiteralValue ||
                !string.Equals(
                    leaf.Field.FieldAccessorReference.Identifier,
                    "type",
                    StringComparison.OrdinalIgnoreCase) ||
                !NSGSecurityRuleParentOnlyDenyCoverage.HasEvenNotParity(leaf: leaf))
            {
                return;
            }

            if (string.Equals(leaf.Operator.Name, "equals", StringComparison.OrdinalIgnoreCase))
            {
                NSGSecurityRuleParentOnlyDenyCoverage.AddStringValue(
                    token: leaf.Operator.Value,
                    selectedResourceTypes: selectedResourceTypes);
                return;
            }

            if (!string.Equals(leaf.Operator.Name, "in", StringComparison.OrdinalIgnoreCase) ||
                leaf.Operator.Value is not JArray values)
            {
                return;
            }

            foreach (var value in values)
            {
                NSGSecurityRuleParentOnlyDenyCoverage.AddStringValue(
                    token: value,
                    selectedResourceTypes: selectedResourceTypes);
            }
        }

        private static void AddStringValue(JToken token, HashSet<string> selectedResourceTypes)
        {
            if (token.Type != JTokenType.String)
            {
                return;
            }

            var value = token.Value<string>();
            if (!string.IsNullOrEmpty(value))
            {
                _ = selectedResourceTypes.Add(value);
            }
        }

        private static bool HasEvenNotParity(LeafCondition leaf)
        {
            var notCount = leaf.PathSegments.Count(
                segment => string.Equals(segment, "not", StringComparison.Ordinal));

            return notCount % 2 == 0;
        }

        private static bool IsParentSecurityRulesAlias(string identifier)
        {
            return identifier.StartsWith(
                    NSGSecurityRuleParentOnlyDenyCoverage.ParentSecurityRulesAliasPrefix,
                    StringComparison.OrdinalIgnoreCase) &&
                (identifier.Length == NSGSecurityRuleParentOnlyDenyCoverage.ParentSecurityRulesAliasPrefix.Length ||
                identifier[NSGSecurityRuleParentOnlyDenyCoverage.ParentSecurityRulesAliasPrefix.Length] == '.');
        }
    }
}
