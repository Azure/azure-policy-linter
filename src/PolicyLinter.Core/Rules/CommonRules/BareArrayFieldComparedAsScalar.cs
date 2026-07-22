// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules
{
    using System;
    using System.Linq;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions.EvaluationHelpers;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Microsoft.WindowsAzure.ResourceStack.Common.Collections;
    using Newtonsoft.Json.Linq;

    /// <summary>
    /// Detects bare array field aliases used with scalar comparison operators and literal scalar values.
    /// </summary>
    public sealed class BareArrayFieldComparedAsScalar : LinterRule<LeafCondition>
    {
        private const string RuleTitle = "Bare Array Field Compared as Scalar";
        private const string RuleDescription =
            "The field alias: '{0}' resolves to the whole array and is used with the scalar comparison operator '{1}'. " +
            "Use a '[*]' alias or field count to compare array members, or use 'exists' to check whether the property is present.";

        private static readonly OrdinalInsensitiveHashSet ScalarComparisonOperators = new OrdinalInsensitiveHashSet
        {
            "equals",
            "notEquals",
            "like",
            "notLike",
            "match",
            "notMatch",
            "matchInsensitively",
            "notMatchInsensitively",
            "greater",
            "greaterOrEquals",
            "less",
            "lessOrEquals",
        };

        /// <summary>
        /// Initializes a new instance of the <see cref="BareArrayFieldComparedAsScalar"/> class.
        /// </summary>
        public BareArrayFieldComparedAsScalar() : base(
            identifier: "bare-array-field-compared-as-scalar",
            category: Category.ResourceFields,
            title: BareArrayFieldComparedAsScalar.RuleTitle,
            descriptionFormat: BareArrayFieldComparedAsScalar.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(LeafCondition expression, LinterContext context)
        {
            var field = expression.Field;
            var fieldReference = field?.FieldAccessorReference;
            if (field == null ||
                fieldReference == null ||
                !field.HasLiteralValue ||
                !fieldReference.IsResolvedFieldReference() ||
                !FieldPathHelper.IsFieldAlias(fieldReference.Identifier) ||
                FieldPathHelper.IsArrayAlias(fieldReference.Identifier))
            {
                return Array.Empty<LinterOutput>();
            }

            var comparisonOperator = expression.Operator;
            if (comparisonOperator == null ||
                !BareArrayFieldComparedAsScalar.ScalarComparisonOperators.Contains(comparisonOperator.Name) ||
                !BareArrayFieldComparedAsScalar.IsLiteralScalar(comparisonOperator))
            {
                return Array.Empty<LinterOutput>();
            }

            var existingMetadata = fieldReference.ResourcePropertyMetadata
                .Where(metadata => metadata.Exists)
                .ToArray();

            if (existingMetadata.Length == 0 ||
                existingMetadata.Any(metadata => !string.Equals(metadata.Type, "Array", StringComparison.OrdinalIgnoreCase)))
            {
                return Array.Empty<LinterOutput>();
            }

            return new[]
            {
                this.CreateWarning(field, fieldReference.Identifier, comparisonOperator.Name),
            };
        }

        private static bool IsLiteralScalar(Property property)
        {
            if (!property.HasLiteralValue || property.Value is not JValue value)
            {
                return false;
            }

            return value.Type == JTokenType.String ||
                value.Type == JTokenType.Integer ||
                value.Type == JTokenType.Float ||
                value.Type == JTokenType.Boolean;
        }
    }
}
