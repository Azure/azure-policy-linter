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
    using Microsoft.Azure.Policy.PolicyLinter.Core.Extensions;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Metadata;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Microsoft.WindowsAzure.ResourceStack.Common.Collections;
    using Newtonsoft.Json.Linq;

    /// <summary>
    /// Detects an ordering condition ('greater', 'greaterOrEquals', 'less', or 'lessOrEquals') whose
    /// field alias has a known data type that cannot be ordered against the comparison value's type.
    /// The comparison throws at evaluation, which fails the policy and implicitly denies the resource.
    /// </summary>
    public sealed class OrderingOperatorOnIncompatibleFieldType : LinterRule<LeafCondition>
    {
        private const string RuleTitle = "Ordering Operator on Incompatible Field Type";
        private const string RuleDescription = "The field alias '{0}' is of type '{1}' and cannot be ordered with the '{2}' operator against a value of type '{3}'. The comparison throws at evaluation, which fails the policy and implicitly denies the resource.";

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

            var fieldTypes = fieldReference.ResourcePropertyMetadata
                .Where(metadata => metadata.Exists && OrderingOperatorOnIncompatibleFieldType.IsKnownType(metadata.Type))
                .Select(metadata => metadata.Type)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();

            if (fieldTypes.Length == 0)
            {
                return Array.Empty<LinterOutput>();
            }

            var valueIsNumericOrDate = OrderingOperatorOnIncompatibleFieldType.IsNumericOrDate(expression.Operator.Value);
            if (fieldTypes.Any(fieldType => OrderingOperatorOnIncompatibleFieldType.IsOrderableWithValue(fieldType, valueIsNumericOrDate)))
            {
                return Array.Empty<LinterOutput>();
            }

            var fieldTypeName = string.Join("/", fieldTypes.Select(OrderingOperatorOnIncompatibleFieldType.FriendlyTypeName).Distinct());
            var valueTypeName = OrderingOperatorOnIncompatibleFieldType.FriendlyValueTypeName(expression.Operator.Value);

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
        /// Determines whether a field of the given data type can be ordered against the comparison value.
        /// </summary>
        /// <param name="fieldType">The field's alias data type.</param>
        /// <param name="valueIsNumericOrDate">Whether the comparison value is a number or a date.</param>
        private static bool IsOrderableWithValue(string fieldType, bool valueIsNumericOrDate)
        {
            if (fieldType.Equals(AliasPathTokenType.Integer.ToString(), StringComparison.OrdinalIgnoreCase) ||
                fieldType.Equals(AliasPathTokenType.Number.ToString(), StringComparison.OrdinalIgnoreCase))
            {
                // A numeric field orders against a number or a date; any other value type throws.
                return valueIsNumericOrDate;
            }

            // Boolean, object, and array fields can't be ordered against any value. A string field is treated as
            // compatible: it orders lexicographically against strings, dates, and numbers.
            return !fieldType.Equals(AliasPathTokenType.Boolean.ToString(), StringComparison.OrdinalIgnoreCase) &&
                !fieldType.Equals(AliasPathTokenType.Object.ToString(), StringComparison.OrdinalIgnoreCase) &&
                !fieldType.Equals(AliasPathTokenType.Array.ToString(), StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Determines whether a literal comparison value is a number or an ISO 8601 date.
        /// </summary>
        /// <param name="value">The comparison value.</param>
        private static bool IsNumericOrDate(JToken value)
        {
            return value.Type is JTokenType.Integer or JTokenType.Float ||
                (value.Type == JTokenType.String && (value.Value<string>() ?? string.Empty).TryParseISO8601UniversalDateTime(out _));
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
        /// <param name="value">The comparison value.</param>
        private static string FriendlyValueTypeName(JToken value)
        {
            return value.Type switch
            {
                JTokenType.Integer or JTokenType.Float => "number",
                JTokenType.String => "string",
                JTokenType.Boolean => "boolean",
                JTokenType.Object => "object",
                JTokenType.Array => "array",
                JTokenType.Null => "null",
                _ => value.Type.ToString().ToLowerInvariant(),
            };
        }
    }
}
