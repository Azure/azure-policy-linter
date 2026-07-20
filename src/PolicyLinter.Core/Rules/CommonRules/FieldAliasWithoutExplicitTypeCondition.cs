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
    using Newtonsoft.Json.Linq;

    /// <summary>
    /// Detects policy rules that use field aliases without an explicit positive type condition.
    /// </summary>
    public sealed class FieldAliasWithoutExplicitTypeCondition : LinterRule<IfCondition>
    {
        private const string RuleTitle = "Field Alias Without Explicit Type Condition";
        private const string RuleDescription =
            "The field aliases resolve to resource types: '{0}' without an explicit 'type' equals or in condition. Add an explicit condition to make the policy's target resource types clear.";

        /// <summary>
        /// Initializes a new instance of the <see cref="FieldAliasWithoutExplicitTypeCondition"/> class.
        /// </summary>
        public FieldAliasWithoutExplicitTypeCondition() : base(
            identifier: "field-alias-without-explicit-type-condition",
            category: Category.BestPractices,
            title: FieldAliasWithoutExplicitTypeCondition.RuleTitle,
            descriptionFormat: FieldAliasWithoutExplicitTypeCondition.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(IfCondition expression, LinterContext context)
        {
            var resourceTypes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var hasExplicitTypeCondition = false;

            var visitor = new PolicyExpressionVisitor
            {
                Visit = (visitedExpression) =>
                {
                    if (visitedExpression is Reference reference)
                    {
                        FieldAliasWithoutExplicitTypeCondition.CollectResourceTypes(reference, resourceTypes);
                    }

                    if (visitedExpression is LeafCondition leaf &&
                        FieldAliasWithoutExplicitTypeCondition.IsExplicitPositiveTypeCondition(leaf))
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

        private static void CollectResourceTypes(Reference reference, HashSet<string> resourceTypes)
        {
            if (!reference.IsResolvedFieldReference() ||
                !FieldPathHelper.IsFieldAlias(reference.Identifier) ||
                !FieldPathHelper.FieldAliasHasFullyQualifiedResourceType(reference.Identifier) ||
                reference.ResourcePropertyMetadata.IsEmpty)
            {
                return;
            }

            foreach (var metadata in reference.ResourcePropertyMetadata)
            {
                if (!string.IsNullOrWhiteSpace(metadata.ResourceType))
                {
                    _ = resourceTypes.Add(metadata.ResourceType);
                }
            }
        }

        private static bool IsExplicitPositiveTypeCondition(LeafCondition leaf)
        {
            var fieldReference = FieldAliasWithoutExplicitTypeCondition.GetComparedFieldReference(leaf);
            var leafOperator = leaf.Operator;

            if (fieldReference == null ||
                !fieldReference.IsResolvedFieldReference() ||
                !string.Equals(fieldReference.Identifier, "type", StringComparison.OrdinalIgnoreCase) ||
                leafOperator == null ||
                !leafOperator.HasLiteralValue ||
                FieldAliasWithoutExplicitTypeCondition.IsNegated(leaf))
            {
                return false;
            }

            if (string.Equals(leafOperator.Name, "equals", StringComparison.OrdinalIgnoreCase))
            {
                return leafOperator.Value.Type == JTokenType.String &&
                    !string.IsNullOrWhiteSpace(leafOperator.Value.ToString());
            }

            if (string.Equals(leafOperator.Name, "in", StringComparison.OrdinalIgnoreCase) &&
                leafOperator.Value is JArray values)
            {
                return values.Any(value =>
                    value.Type == JTokenType.String &&
                    !string.IsNullOrWhiteSpace(value.ToString()));
            }

            return false;
        }

        private static Reference? GetComparedFieldReference(LeafCondition leaf)
        {
            if (leaf.Field?.FieldAccessorReference != null)
            {
                return leaf.Field.FieldAccessorReference;
            }

            if (leaf.Value?.LanguageExpressions.Length != 1)
            {
                return null;
            }

            var languageExpression = leaf.Value.LanguageExpressions[0];
            if (!string.Equals(languageExpression.Expression, leaf.Value.Value.ToString(), StringComparison.Ordinal) ||
                languageExpression.ReferenceKind != ReferenceKind.ResourceField ||
                languageExpression.References.Length != 1)
            {
                return null;
            }

            return languageExpression.References[0];
        }

        private static bool IsNegated(LeafCondition leaf)
        {
            var notCount = leaf.PathSegments.Count(segment =>
                string.Equals(segment, "not", StringComparison.OrdinalIgnoreCase));

            return notCount % 2 != 0;
        }
    }
}
