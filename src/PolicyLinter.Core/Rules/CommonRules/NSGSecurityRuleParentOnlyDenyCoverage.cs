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
        private const string ParentResourceType = "Microsoft.Network/networkSecurityGroups";
        private const string ChildResourceType = "Microsoft.Network/networkSecurityGroups/securityRules";
        private const string ParentSecurityRulesAliasPrefix = "Microsoft.Network/networkSecurityGroups/securityRules[*]";
        private const string RuleTitle = "NSG Security Rule Parent-Only Deny Coverage";
        private const string RuleDescription =
            "This deny-capable definition covers security rules submitted in the parent NSG collection but not independently deployed child security-rule requests. Add equivalent child coverage in this or another policy.";

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
                        selectedResourceTypes.UnionWith(
                            NSGSecurityRuleParentOnlyDenyCoverage.GetSelectedResourceTypes(
                                condition: leaf,
                                considerNotParity: true));
                    }
                    else if (policyExpression is Reference reference &&
                        reference.IsResolvedFieldReference() &&
                        NSGSecurityRuleParentOnlyDenyCoverage.IsParentSecurityRulesAlias(
                            identifier: reference.Identifier))
                    {
                        referencesParentSecurityRulesAlias = true;
                    }
                },
            };

            expression.PolicyRule.If.Visit(visitor);

            if (!selectedResourceTypes.Contains(NSGSecurityRuleParentOnlyDenyCoverage.ParentResourceType) ||
                !referencesParentSecurityRulesAlias ||
                (NSGSecurityRuleParentOnlyDenyCoverage.IsAllMode(mode: expression.Mode) &&
                NSGSecurityRuleParentOnlyDenyCoverage.HasEffectiveChildCoverage(
                    condition: expression.PolicyRule.If.Condition,
                    isNegated: false)))
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

        private static bool HasEffectiveChildCoverage(Condition condition, bool isNegated)
        {
            if (condition is LeafCondition leaf)
            {
                if (isNegated ||
                    NSGSecurityRuleParentOnlyDenyCoverage.ContainsParentSecurityRulesAlias(
                        condition: leaf))
                {
                    return false;
                }

                return NSGSecurityRuleParentOnlyDenyCoverage.GetSelectedResourceTypes(
                        condition: leaf,
                        considerNotParity: false)
                    .Contains(
                        NSGSecurityRuleParentOnlyDenyCoverage.ChildResourceType,
                        StringComparer.OrdinalIgnoreCase);
            }

            if (condition is not Quantifier quantifier)
            {
                return false;
            }

            if (quantifier.Not != null)
            {
                return NSGSecurityRuleParentOnlyDenyCoverage.HasEffectiveChildCoverage(
                    condition: quantifier.Not,
                    isNegated: !isNegated);
            }

            var childConditions = quantifier.AllOf ?? quantifier.AnyOf;
            if (childConditions == null)
            {
                return false;
            }

            var useAllOf = (quantifier.AllOf != null) != isNegated;
            if (!useAllOf)
            {
                return childConditions.Value.Any(
                    child => NSGSecurityRuleParentOnlyDenyCoverage.HasEffectiveChildCoverage(
                        condition: child,
                        isNegated: isNegated));
            }

            return childConditions.Value.All(
                    child => NSGSecurityRuleParentOnlyDenyCoverage.CanApplyToChild(
                        condition: child,
                        isNegated: isNegated)) &&
                childConditions.Value.Any(
                    child => NSGSecurityRuleParentOnlyDenyCoverage.HasEffectiveChildCoverage(
                        condition: child,
                        isNegated: isNegated));
        }

        private static bool CanApplyToChild(Condition condition, bool isNegated)
        {
            if (condition is LeafCondition leaf)
            {
                if (NSGSecurityRuleParentOnlyDenyCoverage.ContainsParentSecurityRulesAlias(
                    condition: leaf))
                {
                    return false;
                }

                var fieldReference = NSGSecurityRuleParentOnlyDenyCoverage.GetComparedFieldReference(
                    condition: leaf);
                if (fieldReference?.IsResolvedFieldReference() != true ||
                    !string.Equals(fieldReference.Identifier, "type", StringComparison.OrdinalIgnoreCase))
                {
                    return fieldReference?.IsResolved != false;
                }

                var selectedTypes = NSGSecurityRuleParentOnlyDenyCoverage.GetSelectedResourceTypes(
                    condition: leaf,
                    considerNotParity: false);
                if (selectedTypes.Length == 0)
                {
                    return false;
                }

                var selectsChild = selectedTypes.Contains(
                    NSGSecurityRuleParentOnlyDenyCoverage.ChildResourceType,
                    StringComparer.OrdinalIgnoreCase);
                return isNegated != selectsChild;
            }

            if (condition is not Quantifier quantifier)
            {
                return false;
            }

            if (quantifier.Not != null)
            {
                return NSGSecurityRuleParentOnlyDenyCoverage.CanApplyToChild(
                    condition: quantifier.Not,
                    isNegated: !isNegated);
            }

            var childConditions = quantifier.AllOf ?? quantifier.AnyOf;
            if (childConditions == null)
            {
                return false;
            }

            var useAllOf = (quantifier.AllOf != null) != isNegated;
            return useAllOf
                ? childConditions.Value.All(
                    child => NSGSecurityRuleParentOnlyDenyCoverage.CanApplyToChild(
                        condition: child,
                        isNegated: isNegated))
                : childConditions.Value.Any(
                    child => NSGSecurityRuleParentOnlyDenyCoverage.CanApplyToChild(
                        condition: child,
                        isNegated: isNegated));
        }

        private static bool ContainsParentSecurityRulesAlias(Condition condition)
        {
            var containsAlias = false;
            condition.Visit(new PolicyExpressionVisitor
            {
                Visit = expression =>
                {
                    if (expression is Reference reference &&
                        reference.IsResolvedFieldReference() &&
                        NSGSecurityRuleParentOnlyDenyCoverage.IsParentSecurityRulesAlias(
                            identifier: reference.Identifier))
                    {
                        containsAlias = true;
                    }
                },
            });

            return containsAlias;
        }

        private static string[] GetSelectedResourceTypes(
            LeafCondition condition,
            bool considerNotParity)
        {
            var fieldReference = NSGSecurityRuleParentOnlyDenyCoverage.GetComparedFieldReference(
                condition: condition);
            if (fieldReference?.IsResolvedFieldReference() != true ||
                !string.Equals(fieldReference.Identifier, "type", StringComparison.OrdinalIgnoreCase) ||
                condition.Operator?.HasLiteralValue != true ||
                (considerNotParity &&
                NSGSecurityRuleParentOnlyDenyCoverage.IsUnderOddNotParity(condition: condition)))
            {
                return Array.Empty<string>();
            }

            if (string.Equals(condition.Operator.Name, "equals", StringComparison.OrdinalIgnoreCase))
            {
                var resourceType = condition.Operator.Value.Type == JTokenType.String
                    ? condition.Operator.Value.Value<string>()
                    : null;

                return string.IsNullOrWhiteSpace(resourceType)
                    ? Array.Empty<string>()
                    : new[] { resourceType };
            }

            if (!string.Equals(condition.Operator.Name, "in", StringComparison.OrdinalIgnoreCase) ||
                condition.Operator.Value is not JArray resourceTypes ||
                resourceTypes.Count == 0 ||
                resourceTypes.Any(resourceType => resourceType.Type != JTokenType.String))
            {
                return Array.Empty<string>();
            }

            return resourceTypes
                .Select(resourceType => resourceType.Value<string>()!)
                .Where(resourceType => !string.IsNullOrWhiteSpace(resourceType))
                .ToArray();
        }

        private static Reference? GetComparedFieldReference(LeafCondition condition)
        {
            if (condition.Field?.FieldAccessorReference != null)
            {
                return condition.Field.FieldAccessorReference;
            }

            if (condition.Value?.LanguageExpressions.Length != 1)
            {
                return null;
            }

            var languageExpression = condition.Value.LanguageExpressions[0];
            if (!string.Equals(languageExpression.Expression, condition.Value.Value.ToString(), StringComparison.Ordinal) ||
                languageExpression.ReferenceKind != ReferenceKind.ResourceField ||
                languageExpression.References.Length != 1)
            {
                return null;
            }

            return languageExpression.References[0];
        }

        private static bool IsUnderOddNotParity(LeafCondition condition)
        {
            var notCount = condition.PathSegments.Count(
                segment => string.Equals(segment, "not", StringComparison.Ordinal));

            return notCount % 2 != 0;
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
