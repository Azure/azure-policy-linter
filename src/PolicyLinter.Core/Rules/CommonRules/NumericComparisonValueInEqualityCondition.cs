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
    public sealed class NumericComparisonValueInEqualityCondition : LinterRule<LeafCondition>
    {
        private const string RuleTitle = "Numeric Comparison Value in Equality Condition";
        private const string RuleDescription =
            "The '{0}' condition converts comparison parameter '{1}' of type '{2}' to a string. Numerically equal values with different string representations can compare as unequal. Use the 'equals()' function in a 'value' condition for numeric equality.";

        /// <summary>
        /// Initializes a new instance of the <see cref="NumericComparisonValueInEqualityCondition"/> class.
        /// </summary>
        public NumericComparisonValueInEqualityCondition() : base(
            identifier: "numeric-comparison-value-in-equality-condition",
            category: Category.BestPractices,
            title: NumericComparisonValueInEqualityCondition.RuleTitle,
            descriptionFormat: NumericComparisonValueInEqualityCondition.RuleDescription,
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
                NumericFieldOrValueInEqualityCondition.TryGetNumericParameter(
                    property: comparisonOperator,
                    context: context,
                    parameterName: out var parameterName) &&
                !NumericFieldOrValueInEqualityCondition.TryGetNumericExpression(
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
                        parameterName,
                        parameter.Type),
                };
            }

            return Array.Empty<LinterOutput>();
        }
    }
}
