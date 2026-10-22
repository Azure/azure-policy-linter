// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules
{
    using System;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Microsoft.WindowsAzure.ResourceStack.Common.Extensions;

    /// <summary>
    /// Detects equality conditions whose comparison value is a numeric parameter.
    /// </summary>
    public sealed class NumericParameterInEqualityOperator : LinterRule<LeafCondition>
    {
        private const string RuleTitle = "Numeric Parameter in Equality Operator";
        private const string RuleDescription =
            "The '{0}' operator converts numeric parameter '{1}' to a string before it compares the values, so the number 5 equals the string '5'. To also compare the value types, use the 'equals()' template function in a 'value' condition.";

        /// <summary>
        /// Initializes a new instance of the <see cref="NumericParameterInEqualityOperator"/> class.
        /// </summary>
        public NumericParameterInEqualityOperator() : base(
            identifier: "numeric-parameter-in-equality-operator",
            category: Category.BestPractices,
            title: NumericParameterInEqualityOperator.RuleTitle,
            descriptionFormat: NumericParameterInEqualityOperator.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(LeafCondition expression, LinterContext context)
        {
            var comparisonOperator = expression.Operator;
            if (comparisonOperator != null &&
                (comparisonOperator.Name.EqualsOrdinalInsensitively("equals") ||
                comparisonOperator.Name.EqualsOrdinalInsensitively("notEquals")) &&
                NumericFieldOrValueInEqualityOperator.TryGetNumericParameter(
                    property: comparisonOperator,
                    context: context,
                    parameterName: out var parameterName) &&
                !NumericFieldOrValueInEqualityOperator.TryGetNumericExpression(
                    expression: expression,
                    context: context,
                    numericExpression: out _,
                    description: out _) &&
                context.Parameters!.TryGetValue(key: parameterName, value: out var parameter))
            {
                return new[]
                {
                    this.CreateInformational(
                        comparisonOperator,
                        comparisonOperator.Name,
                        parameterName),
                };
            }

            return Array.Empty<LinterOutput>();
        }
    }
}
