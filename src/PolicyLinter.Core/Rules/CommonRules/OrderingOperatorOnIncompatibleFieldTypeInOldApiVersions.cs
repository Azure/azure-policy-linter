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
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;

    /// <summary>
    /// Detects an ordering condition whose field alias can be ordered against the comparison value in the latest
    /// API version, but has a data type in one or more older API versions that can't. Requests that use those
    /// API versions fail evaluation, which implicitly denies the resource.
    /// </summary>
    public sealed class OrderingOperatorOnIncompatibleFieldTypeInOldApiVersions : LinterRule<LeafCondition>
    {
        private const string RuleTitle = "Ordering Operator on Incompatible Field Type in Old API Versions";
        private const string RuleDescription = "The field alias '{0}' is of type '{1}' in API versions '{2}' and cannot be ordered with the '{3}' operator against a value of type '{4}'. Requests that use these API versions fail evaluation, which implicitly denies the resource.";

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
            if (!OrderingOperatorOnIncompatibleFieldType.TryGetLatestApiVersionMetadata(expression, out var fieldReference, out var latestApiVersionMetadata) ||
                !OrderingOperatorOnIncompatibleFieldType.IsOrderableWithValue(latestApiVersionMetadata.Type, expression.Operator!.Value))
            {
                return Array.Empty<LinterOutput>();
            }

            return fieldReference.ResourcePropertyMetadata
                .Where(metadata => metadata != latestApiVersionMetadata &&
                    metadata.Exists &&
                    OrderingOperatorOnIncompatibleFieldType.IsKnownType(metadata.Type) &&
                    !OrderingOperatorOnIncompatibleFieldType.IsOrderableWithValue(metadata.Type, expression.Operator.Value))
                .GroupBy(metadata => OrderingOperatorOnIncompatibleFieldType.FriendlyTypeName(metadata.Type))
                .Select(group => this.CreateWarning(
                    expression.Operator,
                    fieldReference.Identifier,
                    group.Key,
                    string.Join(", ", group.SelectMany(metadata => metadata.ApiVersions).Distinct().OrderBy(version => version, SuffixAwareApiVersionComparer.Instance)),
                    expression.Operator.Name,
                    OrderingOperatorOnIncompatibleFieldType.FriendlyValueTypeName(expression.Operator.Value)))
                .ToArray();
        }
    }
}
