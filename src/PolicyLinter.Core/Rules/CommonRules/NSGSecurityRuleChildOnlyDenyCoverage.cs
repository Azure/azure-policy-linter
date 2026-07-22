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
            if (!NSGSecurityRuleChildOnlyDenyCoverage.CanSelectDeny(expression.PolicyRule.Then.Effect, context))
            {
                return Array.Empty<LinterOutput>();
            }

            var typeSelections = NSGSecurityRuleChildOnlyDenyCoverage.CollectTypeSelections(expression.PolicyRule.If);
            var selectedResourceTypes = typeSelections.ResourceTypes;
            if (!selectedResourceTypes.Contains(NSGSecurityRuleChildOnlyDenyCoverage.ChildResourceType) ||
                selectedResourceTypes.Contains(NSGSecurityRuleChildOnlyDenyCoverage.ParentResourceType) ||
                typeSelections.HasIndeterminateTypeCondition ||
                typeSelections.ChildSelection == null)
            {
                return Array.Empty<LinterOutput>();
            }

            return new[]
            {
                this.CreateWarning(typeSelections.ChildSelection),
            };
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
                        var selectedTypes = NSGSecurityRuleChildOnlyDenyCoverage.GetSelectedResourceTypes(leafCondition);
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

        private static string[] GetSelectedResourceTypes(LeafCondition condition)
        {
            var fieldReference = NSGSecurityRuleChildOnlyDenyCoverage.GetComparedFieldReference(condition);
            if (fieldReference?.IsResolvedFieldReference() != true ||
                !string.Equals(fieldReference.Identifier, "type", StringComparison.OrdinalIgnoreCase) ||
                condition.Operator?.HasLiteralValue != true ||
                NSGSecurityRuleChildOnlyDenyCoverage.IsUnderOddNotParity(condition))
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
            var fieldReference = NSGSecurityRuleChildOnlyDenyCoverage.GetComparedFieldReference(condition);
            if (fieldReference?.IsResolvedFieldReference() == true &&
                string.Equals(fieldReference.Identifier, "type", StringComparison.OrdinalIgnoreCase))
            {
                return selectedTypes.Length == 0;
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
