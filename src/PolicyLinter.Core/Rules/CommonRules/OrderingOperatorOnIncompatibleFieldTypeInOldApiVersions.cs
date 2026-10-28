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
        private const string RuleDescription = "The field alias '{0}' cannot be ordered with the '{1}' operator against a value of type '{2}' in older API versions of the resource type: '{3}'. Requests that use these API versions fail evaluation, which implicitly denies the resource.";

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
            var match = OrderingOperatorOnIncompatibleFieldType.GetLatestApiVersionMetadata(expression);
            if (match == null || !OrderingOperatorOnIncompatibleFieldType.IsOrderableWithValue(match.Value.Latest.Type, expression.Operator!.Value))
            {
                return Array.Empty<LinterOutput>();
            }

            var incompatibleApiVersions = match.Value.FieldReference.ResourcePropertyMetadata
                .Where(metadata => metadata.Exists &&
                    OrderingOperatorOnIncompatibleFieldType.IsKnownType(metadata.Type) &&
                    !OrderingOperatorOnIncompatibleFieldType.IsOrderableWithValue(metadata.Type, expression.Operator.Value))
                .SelectMany(metadata => metadata.ApiVersions)
                .Distinct()
                .OrderBy(version => version, SuffixAwareApiVersionComparer.Instance)
                .ToArray();

            if (incompatibleApiVersions.Length == 0)
            {
                return Array.Empty<LinterOutput>();
            }

            return new[]
            {
                this.CreateWarning(
                    expression.Operator,
                    match.Value.FieldReference.Identifier,
                    expression.Operator.Name,
                    OrderingOperatorOnIncompatibleFieldType.FriendlyValueTypeName(expression.Operator.Value),
                    string.Join(", ", incompatibleApiVersions)),
            };
        }
    }
}
