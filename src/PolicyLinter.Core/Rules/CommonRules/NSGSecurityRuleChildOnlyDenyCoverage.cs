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

            var selectedResourceTypes = NSGSecurityRuleChildOnlyDenyCoverage.CollectSelectedResourceTypes(expression.PolicyRule.If);
            if (!selectedResourceTypes.Contains(NSGSecurityRuleChildOnlyDenyCoverage.ChildResourceType) ||
                selectedResourceTypes.Contains(NSGSecurityRuleChildOnlyDenyCoverage.ParentResourceType))
            {
                return Array.Empty<LinterOutput>();
            }

            return new[]
            {
                this.CreateWarning(expression.PolicyRule.Then.Effect),
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

        private static HashSet<string> CollectSelectedResourceTypes(IfCondition condition)
        {
            var selectedResourceTypes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var visitor = new PolicyExpressionVisitor
            {
                Visit = policyExpression =>
                {
                    if (policyExpression is LeafCondition leafCondition)
                    {
                        selectedResourceTypes.UnionWith(
                            NSGSecurityRuleChildOnlyDenyCoverage.GetSelectedResourceTypes(leafCondition));
                    }
                },
            };

            condition.Visit(visitor);
            return selectedResourceTypes;
        }

        private static string[] GetSelectedResourceTypes(LeafCondition condition)
        {
            if (condition.Field?.HasLiteralValue != true ||
                !string.Equals(
                    condition.Field.FieldAccessorReference?.Identifier,
                    "type",
                    StringComparison.OrdinalIgnoreCase) ||
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

        private static bool IsUnderOddNotParity(LeafCondition condition)
        {
            var notCount = condition.PathSegments.Count(
                segment => string.Equals(segment, "not", StringComparison.Ordinal));

            return notCount % 2 != 0;
        }
    }
}
