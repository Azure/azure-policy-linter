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
    /// Detects equality conditions with a numeric field, Float parameter, or floating-point literal value.
    /// </summary>
    public sealed class EqualityCheckOnNumericValue : LinterRule<LeafCondition>
    {
        private const string RuleTitle = "Equality Check on Numeric Value";
        private const string RuleDescription =
            "The '{0}' condition compares a numeric value as text ({1}). Numeric formatting can affect the result. Use the 'equals()' function in a 'value' condition for numeric equality.";

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
        /// Initializes a new instance of the <see cref="EqualityCheckOnNumericValue"/> class.
        /// </summary>
        public EqualityCheckOnNumericValue() : base(
            identifier: "equality-check-on-numeric-value",
            category: Category.BestPractices,
            title: EqualityCheckOnNumericValue.RuleTitle,
            descriptionFormat: EqualityCheckOnNumericValue.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(LeafCondition expression, LinterContext context)
        {
            var comparisonOperator = expression.Operator;
            if (comparisonOperator == null ||
                !EqualityCheckOnNumericValue.EqualityOperators.Contains(comparisonOperator.Name))
            {
                return Array.Empty<LinterOutput>();
            }

            var field = expression.Field;
            var fieldReference = expression.Field?.FieldAccessorReference;
            if (field != null &&
                fieldReference != null &&
                field.HasLiteralValue &&
                fieldReference.IsResolvedFieldReference() &&
                FieldPathHelper.IsFieldAlias(fieldReference.Identifier) &&
                fieldReference.ResourcePropertyMetadata.Any(
                    metadata => metadata.Exists && EqualityCheckOnNumericValue.NumericPropertyTypes.Contains(metadata.Type)))
            {
                return new[]
                {
                    this.CreateInformational(
                        field,
                        comparisonOperator.Name,
                        $"field alias '{fieldReference.Identifier}'"),
                };
            }

            if (EqualityCheckOnNumericValue.TryGetFloatParameter(
                property: expression.Value,
                context: context,
                parameterName: out var valueParameterName))
            {
                return new[]
                {
                    this.CreateInformational(
                        expression.Value,
                        comparisonOperator.Name,
                        $"parameter '{valueParameterName}'"),
                };
            }

            if (expression.Value?.HasLiteralValue == true &&
                expression.Value.Value.Type == JTokenType.Float)
            {
                return new[]
                {
                    this.CreateInformational(expression.Value, comparisonOperator.Name, "floating-point literal"),
                };
            }

            if (EqualityCheckOnNumericValue.TryGetFloatParameter(
                property: comparisonOperator,
                context: context,
                parameterName: out var operatorParameterName))
            {
                return new[]
                {
                    this.CreateInformational(
                        comparisonOperator,
                        comparisonOperator.Name,
                        $"parameter '{operatorParameterName}'"),
                };
            }

            return Array.Empty<LinterOutput>();
        }

        private static bool TryGetFloatParameter(
            Property? property,
            LinterContext context,
            out string parameterName)
        {
            parameterName = string.Empty;

            return property != null &&
                property.IsSimpleParameterReference(parameterName: out parameterName) &&
                context.Parameters != null &&
                context.Parameters.TryGetValue(key: parameterName, value: out var parameter) &&
                parameter.Type.EqualsOrdinalInsensitively(PolicyParameterType.Float);
        }
    }
}
