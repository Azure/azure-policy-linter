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
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions.EvaluationHelpers;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;

    /// <summary>
    /// Detects policies that target a resource type through field aliases without an explicit type condition.
    /// </summary>
    public sealed class ImplicitResourceTypeTargeting : LinterRule<IfCondition>
    {
        private const string RuleTitle = "Implicit Resource Type Targeting";
        private const string RuleDescription =
            "The policy targets fields of '{0}' without an explicit 'type' condition, leaving the targeted resource types implicit. Add a 'type' condition using 'equals' or 'in'.";

        /// <summary>
        /// Initializes a new instance of the <see cref="ImplicitResourceTypeTargeting"/> class.
        /// </summary>
        public ImplicitResourceTypeTargeting() : base(
            identifier: "implicit-resource-type-targeting",
            category: Category.BestPractices,
            title: ImplicitResourceTypeTargeting.RuleTitle,
            descriptionFormat: ImplicitResourceTypeTargeting.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(IfCondition expression, LinterContext context)
        {
            var resourceTypes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var hasExplicitTypeCondition = false;

            // A 'type' condition anywhere in the rule counts as a guard, so a policy that guards one
            // logical branch and not another is not reported. TODO: use the linter's resource
            // applicability analysis when it is available to determine the guard per branch.
            var visitor = new PolicyExpressionVisitor
            {
                Visit = (visitedExpression) =>
                {
                    if (visitedExpression is Reference reference && ImplicitResourceTypeTargeting.TryExtractResourceTypeFromReference(reference, out var resourceType))
                    {
                        _ = resourceTypes.Add(resourceType);
                    }

                    if (visitedExpression is LeafCondition leaf &&
                        ImplicitResourceTypeTargeting.IsExplicitTypeCondition(leaf))
                    {
                        hasExplicitTypeCondition = true;
                    }
                }
            };

            expression.Visit(visitor);

            if (resourceTypes.Count == 0 || hasExplicitTypeCondition)
            {
                return Array.Empty<LinterOutput>();
            }

            var formattedResourceTypes = string.Join(
                ", ",
                resourceTypes.OrderBy(resourceType => resourceType, StringComparer.OrdinalIgnoreCase));

            return new[]
            {
                this.CreateInformational(expression, formattedResourceTypes),
            };
        }

        private static bool TryExtractResourceTypeFromReference(Reference reference, out string resourceType)
        {
            resourceType = "Unknown";

            if (!reference.IsResolvedFieldReference() ||
                !FieldPathHelper.IsFieldAlias(reference.Identifier) ||
                !FieldPathHelper.FieldAliasHasFullyQualifiedResourceType(reference.Identifier) ||
                reference.ResourcePropertyMetadata.IsEmpty)
            {
                return false;
            }

            resourceType = FieldPathHelper.GetFieldAliasFullyQualifiedResourceType(reference.Identifier);
            return !string.IsNullOrWhiteSpace(resourceType);

        }

        private static bool IsExplicitTypeCondition(LeafCondition leaf)
        {
            return leaf.Field?.FieldAccessorReference != null &&
                string.Equals(leaf.Field.FieldAccessorReference.Identifier, "type", StringComparison.OrdinalIgnoreCase) &&
                leaf.Operator != null &&
                leaf.Operator.HasLiteralValue &&
                (string.Equals(leaf.Operator.Name, "equals", StringComparison.OrdinalIgnoreCase) ||
                 string.Equals(leaf.Operator.Name, "in", StringComparison.OrdinalIgnoreCase));
        }
    }
}
