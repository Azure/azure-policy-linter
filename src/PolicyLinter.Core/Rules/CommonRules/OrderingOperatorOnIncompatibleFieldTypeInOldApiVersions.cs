// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules
{
    using System;
    using System.Linq;
    using global::Azure.Deployments.ResourceMetadata.ApiVersion;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Extensions;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;

    /// <summary>
    /// Detects an ordering condition whose field alias can be ordered against the comparison value in the latest
    /// API version, but has a data type in one or more older API versions that can't. Requests that use those
    /// API versions fail evaluation, which implicitly denies the resource.
    /// </summary>
    public sealed class OrderingOperatorOnIncompatibleFieldTypeInOldApiVersions : LinterRule<LeafCondition>
    {
        private const string RuleTitle = "Ordering Operator on Incompatible Field Type in Old API Versions";
        private const string RuleDescription = "The field alias '{0}' has a data type in older API versions that cannot be ordered with the '{1}' operator against the comparison value. Requests that use these API versions fail evaluation, which implicitly denies the resource. API versions: '{2}'.";

        /// <summary>
        /// Initializes a new instance of the <see cref="OrderingOperatorOnIncompatibleFieldTypeInOldApiVersions"/> class.
        /// </summary>
        public OrderingOperatorOnIncompatibleFieldTypeInOldApiVersions() : base(
            identifier: "ordering-operator-on-incompatible-field-type-in-old-api-versions",
            category: Category.ResourceFields,
            title: OrderingOperatorOnIncompatibleFieldTypeInOldApiVersions.RuleTitle,
            descriptionFormat: OrderingOperatorOnIncompatibleFieldTypeInOldApiVersions.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(LeafCondition expression, LinterContext context)
        {
            var fieldReference = expression.Field?.FieldAccessorReference;
            if (expression.Operator == null ||
                !OrderingOperatorOnIncompatibleFieldType.OrderingOperators.Contains(expression.Operator.Name) ||
                fieldReference == null ||
                !fieldReference.IsResolvedFieldReference() ||
                !expression.Operator.HasLiteralValue)
            {
                return Array.Empty<LinterOutput>();
            }

            var latestApiVersionMetadata = fieldReference.ResourcePropertyMetadata
                .MaxBy(
                    keySelector: metadata => metadata.ApiVersions.Max(comparer: SuffixAwareApiVersionComparer.Instance),
                    comparer: SuffixAwareApiVersionComparer.Instance);

            var incompatibleApiVersions = fieldReference.ResourcePropertyMetadata
                .Where(metadata => metadata.Exists && !OrderingOperatorOnIncompatibleFieldType.IsOrderableWithValue(metadata.Type, expression.Operator.Value))
                .SelectMany(metadata => metadata.ApiVersions)
                .Distinct()
                .OrderBy(version => version, SuffixAwareApiVersionComparer.Instance)
                .ToArray();

            // An incompatible type in the latest API version is a different, more severe issue.
            if (latestApiVersionMetadata?.Exists != true ||
                !OrderingOperatorOnIncompatibleFieldType.IsOrderableWithValue(latestApiVersionMetadata.Type, expression.Operator.Value) ||
                incompatibleApiVersions.Length == 0)
            {
                return Array.Empty<LinterOutput>();
            }

            return new[]
            {
                this.CreateWarning(expression.Operator, fieldReference.Identifier, expression.Operator.Name, string.Join(", ", incompatibleApiVersions)),
            };
        }
    }
}