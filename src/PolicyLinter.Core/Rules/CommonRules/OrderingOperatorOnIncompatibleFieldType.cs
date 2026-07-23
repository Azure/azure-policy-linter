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
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions.EvaluationHelpers;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Extensions;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Metadata;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Microsoft.WindowsAzure.ResourceStack.Common.Collections;
    using Newtonsoft.Json.Linq;

    /// <summary>
    /// Detects an ordering condition ('greater', 'greaterOrEquals', 'less', or 'lessOrEquals') whose
    /// field alias has a data type in the latest API version that cannot be ordered against the
    /// comparison value's type. The comparison throws at evaluation, which fails the policy and
    /// implicitly denies the resource.
    /// </summary>
    public sealed class OrderingOperatorOnIncompatibleFieldType : LinterRule<LeafCondition>
    {
        private const string RuleTitle = "Ordering Operator on Incompatible Field Type";
        private const string RuleDescription = "The field alias '{0}' is of type '{1}' in the latest API version and cannot be ordered with the '{2}' operator against a value of type '{3}'. The comparison throws at evaluation, which fails the policy and implicitly denies the resource.";

        /// <summary>
        /// The ordering operators, which throw at evaluation when their operand types don't match.
        /// </summary>
        private static readonly OrdinalInsensitiveHashSet OrderingOperators = new OrdinalInsensitiveHashSet
        {
            "greater",
            "greaterOrEquals",
            "less",
            "lessOrEquals",
        };

        /// <summary>
        /// Initializes a new instance of the <see cref="OrderingOperatorOnIncompatibleFieldType"/> class.
        /// </summary>
        public OrderingOperatorOnIncompatibleFieldType() : base(
            identifier: "ordering-operator-on-incompatible-field-type",
            category: Category.ResourceFields,
            title: OrderingOperatorOnIncompatibleFieldType.RuleTitle,
            descriptionFormat: OrderingOperatorOnIncompatibleFieldType.RuleDescription,
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

            if (latestApiVersionMetadata == null ||
                !latestApiVersionMetadata.Exists ||
                !OrderingOperatorOnIncompatibleFieldType.IsKnownType(latestApiVersionMetadata.Type))
            {
                return Array.Empty<LinterOutput>();
            }

            var valueType = OrderingOperatorOnIncompatibleFieldType.ClassifyValue(expression.Operator.Value);
            if (OrderingOperatorOnIncompatibleFieldType.IsOrderableWithValue(latestApiVersionMetadata.Type, valueType))
            {
                return Array.Empty<LinterOutput>();
            }

            var fieldTypeName = OrderingOperatorOnIncompatibleFieldType.FriendlyTypeName(latestApiVersionMetadata.Type);
            var valueTypeName = OrderingOperatorOnIncompatibleFieldType.FriendlyValueTypeName(valueType, expression.Operator.Value);

            return new[]
            {
                this.CreateError(expression.Operator, fieldReference.Identifier, fieldTypeName, expression.Operator.Name, valueTypeName),
            };
        }

        /// <summary>
        /// Determines whether the alias data type is known. Unresolved, unspecified, or 'any' types can hold
        /// values of any shape, so the rule can't decide their ordering compatibility and stays silent.
        /// </summary>
        /// <param name="type">The alias data type.</param>
        private static bool IsKnownType(string type)
        {
            return !string.IsNullOrEmpty(type) &&
                !type.Equals(AliasPathTokenType.NotSpecified.ToString(), StringComparison.OrdinalIgnoreCase) &&
                !type.Equals(AliasPathTokenType.Any.ToString(), StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// The type of a literal comparison value, which determines the condition type that the field's
        /// type must match. Azure Policy throws when the field type doesn't match the condition type.
        /// </summary>
        private enum ComparisonValueType
        {
            /// <summary>A number (integer or float).</summary>
            Numeric,

            /// <summary>A string that parses as an ISO 8601 date.</summary>
            Date,

            /// <summary>A string that isn't a date.</summary>
            String,

            /// <summary>Any other value (boolean, object, array, or null).</summary>
            Other,
        }

        /// <summary>
        /// Determines whether a field of the given data type can be ordered against the comparison value.
        /// Azure Policy throws when the field's type doesn't match the comparison value's condition type.
        /// </summary>
        /// <param name="fieldType">The field's alias data type.</param>
        /// <param name="valueType">The comparison value's type.</param>
        private static bool IsOrderableWithValue(string fieldType, ComparisonValueType valueType)
        {
            if (fieldType.Equals(AliasPathTokenType.Integer.ToString(), StringComparison.OrdinalIgnoreCase) ||
                fieldType.Equals(AliasPathTokenType.Number.ToString(), StringComparison.OrdinalIgnoreCase))
            {
                // A numeric field orders only against a number; a string or date condition type throws.
                return valueType == ComparisonValueType.Numeric;
            }

            if (fieldType.Equals(AliasPathTokenType.String.ToString(), StringComparison.OrdinalIgnoreCase))
            {
                // Dates are stored as strings, so a string field orders against a string or a date, but a
                // number condition type throws.
                return valueType is ComparisonValueType.String or ComparisonValueType.Date;
            }

            // Boolean, object, and array fields can't be ordered against any value.
            return false;
        }

        /// <summary>
        /// Classifies a literal comparison value into the condition type it produces.
        /// </summary>
        /// <param name="value">The comparison value.</param>
        private static ComparisonValueType ClassifyValue(JToken value)
        {
            if (value.Type is JTokenType.Integer or JTokenType.Float)
            {
                return ComparisonValueType.Numeric;
            }

            if (value.Type == JTokenType.String)
            {
                return (value.Value<string>() ?? string.Empty).TryParseISO8601UniversalDateTime(out _)
                    ? ComparisonValueType.Date
                    : ComparisonValueType.String;
            }

            return ComparisonValueType.Other;
        }

        /// <summary>
        /// Maps an alias data type to a name for the failure message.
        /// </summary>
        /// <param name="type">The alias data type.</param>
        private static string FriendlyTypeName(string type)
        {
            return type.Equals(AliasPathTokenType.Integer.ToString(), StringComparison.OrdinalIgnoreCase) ||
                type.Equals(AliasPathTokenType.Number.ToString(), StringComparison.OrdinalIgnoreCase)
                    ? "number"
                    : type.ToLowerInvariant();
        }

        /// <summary>
        /// Maps a literal comparison value to a type name for the failure message.
        /// </summary>
        /// <param name="valueType">The comparison value's classified type.</param>
        /// <param name="value">The comparison value.</param>
        private static string FriendlyValueTypeName(ComparisonValueType valueType, JToken value)
        {
            return valueType switch
            {
                ComparisonValueType.Numeric => "number",
                ComparisonValueType.Date => "date",
                ComparisonValueType.String => "string",
                _ => value.Type.ToString().ToLowerInvariant(),
            };
        }
    }
}
