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
    /// Detects deny-capable policies that select the network security group security rule
    /// child resource type without selecting the parent network security group resource type.
    /// </summary>
    public sealed class NSGSecurityRuleChildOnlyDenyCoverage : LinterRule<PolicyDefinitionProperties>
    {
        private const string ParentResourceType = "Microsoft.Network/networkSecurityGroups";
        private const string ChildResourceType = "Microsoft.Network/networkSecurityGroups/securityRules";
        private const string ParentSecurityRulesAliasPrefix = "Microsoft.Network/networkSecurityGroups/securityRules[*]";
        private const string ChildSecurityRulesAliasPrefix = ChildResourceType + "/";
        private const string RuleTitle = "NSG Security Rule Child-Only Deny Coverage";
        private const string RuleDescription =
            "This deny-capable definition covers the child security-rule request path but not changes submitted through the parent NSG 'securityRules' collection. Add equivalent parent coverage in this or another policy.";

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
            if (!NSGSecurityRuleChildOnlyDenyCoverage.IsAllMode(mode: expression.Mode) ||
                !NSGSecurityRuleChildOnlyDenyCoverage.CanSelectDeny(
                    effect: expression.PolicyRule.Then.Effect,
                    context: context))
            {
                return Array.Empty<LinterOutput>();
            }

            var typeSelections = NSGSecurityRuleChildOnlyDenyCoverage.CollectTypeSelections(
                condition: expression.PolicyRule.If);
            if (!typeSelections.ResourceTypes.Contains(NSGSecurityRuleChildOnlyDenyCoverage.ChildResourceType) ||
                typeSelections.HasIndeterminateTypeCondition ||
                typeSelections.ChildSelection == null)
            {
                return Array.Empty<LinterOutput>();
            }

            if (!NSGSecurityRuleChildOnlyDenyCoverage.HasEffectiveCoverage(
                condition: expression.PolicyRule.If.Condition,
                targetResourceType: NSGSecurityRuleChildOnlyDenyCoverage.ChildResourceType,
                isNegated: false) ||
                NSGSecurityRuleChildOnlyDenyCoverage.HasEffectiveCoverage(
                condition: expression.PolicyRule.If.Condition,
                targetResourceType: NSGSecurityRuleChildOnlyDenyCoverage.ParentResourceType,
                isNegated: false))
            {
                return Array.Empty<LinterOutput>();
            }

            return new[]
            {
                this.CreateWarning(expression: typeSelections.ChildSelection),
            };
        }

        private static bool IsAllMode(Property? mode)
        {
            return mode?.HasLiteralValue == true &&
                mode.Value.Type == JTokenType.String &&
                string.Equals(mode.Value.Value<string>(), "all", StringComparison.OrdinalIgnoreCase);
        }

        private static bool CanSelectDeny(Property effect, LinterContext context)
        {
            if (effect.HasLiteralValue)
            {
                return effect.Value.Type == JTokenType.String &&
                    string.Equals(effect.Value.Value<string>(), "deny", StringComparison.OrdinalIgnoreCase);
            }

            if (!effect.HasSimpleParameterizedValue(context: context, out _, out var allowedValues, out _))
            {
                return false;
            }

            return allowedValues == null ||
                allowedValues.Any(value => string.Equals(value, "deny", StringComparison.OrdinalIgnoreCase));
        }

        private static TypeSelections CollectTypeSelections(IfCondition condition)
        {
            var selectedResourceTypes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            Property? childSelection = null;
            var hasIndeterminateTypeCondition = false;
            var visitor = new PolicyExpressionVisitor
            {
                Visit = policyExpression =>
                {
                    if (policyExpression is LeafCondition leafCondition)
                    {
                        var selectedTypes = NSGSecurityRuleChildOnlyDenyCoverage.GetSelectedResourceTypes(
                            condition: leafCondition,
                            considerNotParity: true);
                        selectedResourceTypes.UnionWith(selectedTypes);

                        if (childSelection == null &&
                            selectedTypes.Contains(
                                NSGSecurityRuleChildOnlyDenyCoverage.ChildResourceType,
                                StringComparer.OrdinalIgnoreCase))
                        {
                            childSelection = leafCondition.Operator;
                        }

                        hasIndeterminateTypeCondition |=
                            NSGSecurityRuleChildOnlyDenyCoverage.HasIndeterminateTypeCondition(
                                condition: leafCondition,
                                selectedTypes: selectedTypes);
                    }
                },
            };

            condition.Visit(visitor);
            return new TypeSelections(
                ResourceTypes: selectedResourceTypes,
                ChildSelection: childSelection,
                HasIndeterminateTypeCondition: hasIndeterminateTypeCondition);
        }

        private static bool HasEffectiveCoverage(
            Condition condition,
            string targetResourceType,
            bool isNegated)
        {
            if (condition is LeafCondition leaf)
            {
                if (isNegated ||
                    NSGSecurityRuleChildOnlyDenyCoverage.ContainsIncompatibleAlias(
                        condition: leaf,
                        targetResourceType: targetResourceType))
                {
                    return false;
                }

                return NSGSecurityRuleChildOnlyDenyCoverage.GetSelectedResourceTypes(
                        condition: leaf,
                        considerNotParity: false)
                    .Contains(
                        targetResourceType,
                        StringComparer.OrdinalIgnoreCase);
            }

            if (condition is not Quantifier quantifier)
            {
                return false;
            }

            if (quantifier.Not != null)
            {
                return NSGSecurityRuleChildOnlyDenyCoverage.HasEffectiveCoverage(
                    condition: quantifier.Not,
                    targetResourceType: targetResourceType,
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
                    child => NSGSecurityRuleChildOnlyDenyCoverage.HasEffectiveCoverage(
                        condition: child,
                        targetResourceType: targetResourceType,
                        isNegated: isNegated));
            }

            return childConditions.Value.All(
                    child => NSGSecurityRuleChildOnlyDenyCoverage.CanApplyToResourceType(
                        condition: child,
                        targetResourceType: targetResourceType,
                        isNegated: isNegated)) &&
                childConditions.Value.Any(
                    child => NSGSecurityRuleChildOnlyDenyCoverage.HasEffectiveCoverage(
                        condition: child,
                        targetResourceType: targetResourceType,
                        isNegated: isNegated));
        }

        private static bool CanApplyToResourceType(
            Condition condition,
            string targetResourceType,
            bool isNegated)
        {
            if (condition is LeafCondition leaf)
            {
                if (NSGSecurityRuleChildOnlyDenyCoverage.ContainsIncompatibleAlias(
                    condition: leaf,
                    targetResourceType: targetResourceType))
                {
                    return false;
                }

                var fieldReference = NSGSecurityRuleChildOnlyDenyCoverage.GetComparedFieldReference(
                    condition: leaf);
                if (fieldReference?.IsResolvedFieldReference() != true ||
                    !string.Equals(fieldReference.Identifier, "type", StringComparison.OrdinalIgnoreCase))
                {
                    return fieldReference?.IsResolved != false;
                }

                var selectedTypes = NSGSecurityRuleChildOnlyDenyCoverage.GetSelectedResourceTypes(
                    condition: leaf,
                    considerNotParity: false);
                if (selectedTypes.Length == 0)
                {
                    return false;
                }

                var selectsTarget = selectedTypes.Contains(
                    targetResourceType,
                    StringComparer.OrdinalIgnoreCase);
                return isNegated != selectsTarget;
            }

            if (condition is not Quantifier quantifier)
            {
                return false;
            }

            if (quantifier.Not != null)
            {
                return NSGSecurityRuleChildOnlyDenyCoverage.CanApplyToResourceType(
                    condition: quantifier.Not,
                    targetResourceType: targetResourceType,
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
                    child => NSGSecurityRuleChildOnlyDenyCoverage.CanApplyToResourceType(
                        condition: child,
                        targetResourceType: targetResourceType,
                        isNegated: isNegated))
                : childConditions.Value.Any(
                    child => NSGSecurityRuleChildOnlyDenyCoverage.CanApplyToResourceType(
                        condition: child,
                        targetResourceType: targetResourceType,
                        isNegated: isNegated));
        }

        private static bool ContainsIncompatibleAlias(
            Condition condition,
            string targetResourceType)
        {
            var containsAlias = false;
            condition.Visit(new PolicyExpressionVisitor
            {
                Visit = expression =>
                {
                    if (expression is Reference reference &&
                        reference.IsResolvedFieldReference())
                    {
                        containsAlias |= string.Equals(
                            targetResourceType,
                            NSGSecurityRuleChildOnlyDenyCoverage.ParentResourceType,
                            StringComparison.OrdinalIgnoreCase)
                            ? reference.Identifier.StartsWith(
                                NSGSecurityRuleChildOnlyDenyCoverage.ChildSecurityRulesAliasPrefix,
                                StringComparison.OrdinalIgnoreCase)
                            : NSGSecurityRuleChildOnlyDenyCoverage.IsParentSecurityRulesAlias(
                                identifier: reference.Identifier);
                    }
                },
            });

            return containsAlias;
        }

        private static bool IsParentSecurityRulesAlias(string identifier)
        {
            return identifier.StartsWith(
                    NSGSecurityRuleChildOnlyDenyCoverage.ParentSecurityRulesAliasPrefix,
                    StringComparison.OrdinalIgnoreCase) &&
                (identifier.Length == NSGSecurityRuleChildOnlyDenyCoverage.ParentSecurityRulesAliasPrefix.Length ||
                identifier[NSGSecurityRuleChildOnlyDenyCoverage.ParentSecurityRulesAliasPrefix.Length] == '.');
        }

        private static string[] GetSelectedResourceTypes(
            LeafCondition condition,
            bool considerNotParity)
        {
            var fieldReference = NSGSecurityRuleChildOnlyDenyCoverage.GetComparedFieldReference(
                condition: condition);
            if (fieldReference?.IsResolvedFieldReference() != true ||
                !string.Equals(fieldReference.Identifier, "type", StringComparison.OrdinalIgnoreCase) ||
                condition.Operator?.HasLiteralValue != true ||
                (considerNotParity &&
                NSGSecurityRuleChildOnlyDenyCoverage.IsUnderOddNotParity(condition: condition)))
            {
                return Array.Empty<string>();
            }

            if (string.Equals(condition.Operator.Name, "equals", StringComparison.Ordinal))
            {
                var resourceType = condition.Operator.Value.Type == JTokenType.String
                    ? condition.Operator.Value.Value<string>()
                    : null;

                return string.IsNullOrWhiteSpace(resourceType)
                    ? Array.Empty<string>()
                    : new[] { resourceType };
            }

            if (!string.Equals(condition.Operator.Name, "in", StringComparison.Ordinal) ||
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

        private static bool HasIndeterminateTypeCondition(
            LeafCondition condition,
            string[] selectedTypes)
        {
            var fieldReference = NSGSecurityRuleChildOnlyDenyCoverage.GetComparedFieldReference(
                condition: condition);
            if (fieldReference?.IsResolvedFieldReference() == true &&
                string.Equals(fieldReference.Identifier, "type", StringComparison.OrdinalIgnoreCase))
            {
                return selectedTypes.Length == 0 &&
                    NSGSecurityRuleChildOnlyDenyCoverage.GetSelectedResourceTypes(
                        condition: condition,
                        considerNotParity: false).Length == 0;
            }

            return condition.Field?.HasLiteralValue == false;
        }

        private static bool IsUnderOddNotParity(LeafCondition condition)
        {
            var notCount = condition.PathSegments.Count(
                segment => string.Equals(segment, "not", StringComparison.Ordinal));

            return notCount % 2 != 0;
        }

        private sealed record TypeSelections(
            HashSet<string> ResourceTypes,
            Property? ChildSelection,
            bool HasIndeterminateTypeCondition);
    }
}
