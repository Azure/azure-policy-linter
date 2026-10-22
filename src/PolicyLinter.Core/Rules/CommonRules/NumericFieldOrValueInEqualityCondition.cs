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
    using Microsoft.WindowsAzure.ResourceStack.Common.Extensions;
    using Newtonsoft.Json.Linq;

    /// <summary>
    /// Detects equality conditions whose field or value resolves to a number.
    /// </summary>
    public sealed class NumericFieldOrValueInEqualityCondition : LinterRule<LeafCondition>
    {
        private const string RuleTitle = "Numeric Field or Value in Equality Condition";
        private const string RuleDescription =
            "The '{0}' condition converts {1} to a string before comparison. Numerically equal values with different string representations can compare as unequal. Use the 'equals()' function in a 'value' condition for numeric equality.";

        private static readonly OrdinalInsensitiveHashSet EqualityOperators = new OrdinalInsensitiveHashSet
        {
            "equals",
            "notEquals",
        };

        private static readonly OrdinalInsensitiveHashSet NumericPropertyTypes = new OrdinalInsensitiveHashSet
        {
            "Integer",
            "Number",
        };

        /// <summary>
        /// Initializes a new instance of the <see cref="NumericFieldOrValueInEqualityCondition"/> class.
        /// </summary>
        public NumericFieldOrValueInEqualityCondition() : base(
            identifier: "numeric-field-or-value-in-equality-condition",
            category: Category.BestPractices,
            title: NumericFieldOrValueInEqualityCondition.RuleTitle,
            descriptionFormat: NumericFieldOrValueInEqualityCondition.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(LeafCondition expression, LinterContext context)
        {
            var comparisonOperator = expression.Operator;
            if (comparisonOperator != null &&
                NumericFieldOrValueInEqualityCondition.EqualityOperators.Contains(comparisonOperator.Name) &&
                NumericFieldOrValueInEqualityCondition.TryGetNumericExpression(
                    expression: expression,
                    context: context,
                    numericExpression: out var numericExpression,
                    description: out var description))
            {
                return new[]
                {
                    this.CreateInformational(numericExpression, comparisonOperator.Name, description),
                };
            }

            return Array.Empty<LinterOutput>();
        }

        internal static bool TryGetNumericExpression(
            LeafCondition expression,
            LinterContext context,
            out Property? numericExpression,
            out string description)
        {
            var field = expression.Field;
            var fieldReference = field?.FieldAccessorReference;
            if (field != null &&
                fieldReference != null &&
                field.HasLiteralValue &&
                fieldReference.IsResolvedFieldReference() &&
                FieldPathHelper.IsFieldAlias(fieldReference.Identifier) &&
                fieldReference.ResourcePropertyMetadata.Any(
                    metadata => metadata.Exists &&
                    NumericFieldOrValueInEqualityCondition.NumericPropertyTypes.Contains(metadata.Type)))
            {
                numericExpression = field;
                description = $"field alias '{fieldReference.Identifier}'";
                return true;
            }

            var value = expression.Value;
            if (NumericFieldOrValueInEqualityCondition.TryGetNumericParameter(
                property: value,
                context: context,
                parameterName: out var parameterName))
            {
                numericExpression = value;
                description = $"value parameter '{parameterName}'";
                return true;
            }

            if (value?.HasLiteralValue == true &&
                value.Value.Type is JTokenType.Integer or JTokenType.Float)
            {
                numericExpression = value;
                description = "the numeric value";
                return true;
            }

            numericExpression = null;
            description = string.Empty;
            return false;
        }

        internal static bool TryGetNumericParameter(
            Property? property,
            LinterContext context,
            out string parameterName)
        {
            parameterName = string.Empty;

            return property != null &&
                property.IsSimpleParameterReference(parameterName: out parameterName) &&
                context.Parameters != null &&
                context.Parameters.TryGetValue(key: parameterName, value: out var parameter) &&
                (parameter.Type.EqualsOrdinalInsensitively(PolicyParameterType.Integer) ||
                parameter.Type.EqualsOrdinalInsensitively(PolicyParameterType.Float));
        }
    }
}
