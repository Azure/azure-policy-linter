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
    /// Detects array field aliases compared against a literal scalar value.
    /// </summary>
    public sealed class ArrayComparedAsScalar : LinterRule<LeafCondition>
    {
        private const string RuleTitle = "Array Compared as Scalar";
        private const string RuleDescription =
            "The field alias: '{0}' refers to an entire array, so comparing it with '{1}' is an invalid comparison that always evaluates to false. Use a field count expression to apply the condition to the array members, or remove the condition.";

        // Ordering operators are omitted: an array field cannot be ordered against any value, so
        // OrderingOperatorOnIncompatibleFieldType already reports every such condition as an error.
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
            "contains",
            "notContains",
        };

        /// <summary>
        /// Initializes a new instance of the <see cref="ArrayComparedAsScalar"/> class.
        /// </summary>
        public ArrayComparedAsScalar() : base(
            identifier: "array-compared-as-scalar",
            category: Category.ResourceFields,
            title: ArrayComparedAsScalar.RuleTitle,
            descriptionFormat: ArrayComparedAsScalar.RuleDescription,
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
                !ArrayComparedAsScalar.ScalarComparisonOperators.Contains(comparisonOperator.Name) ||
                !ArrayComparedAsScalar.IsLiteralScalar(comparisonOperator))
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
